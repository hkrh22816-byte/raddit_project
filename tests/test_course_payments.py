"""Payment integration checks; all data and uploads use a disposable directory.
Run: python -m unittest discover -s tests -v
No requests are sent to SwiftPay and no real database credentials are used.
"""
import hashlib
import hmac
import importlib
from io import BytesIO
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


class CoursePaymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if 'app' in sys.modules:
            raise RuntimeError('Run these isolated payment tests in a fresh Python process')
        cls.tmp = tempfile.TemporaryDirectory(prefix='rabbit-payment-tests-')
        cls.env = patch.dict(os.environ, {
            'DATABASE_URL': 'sqlite:///' + str(Path(cls.tmp.name) / 'test.sqlite'),
            'PERSISTENT_STORAGE_PATH': cls.tmp.name,
            'SECRET_KEY': 'test-only-session-secret',
            'SWIFTPAY_MODE': 'live',
            'SWIFTPAY_LIVE_API_KEY': 'spi_live_test_fixture',
            'SWIFTPAY_LIVE_WEBHOOK_SECRET': 'whsec_test_fixture',
            'RATELIMIT_STORAGE_URI': 'memory://',
            'ADMIN_USERNAME': '', 'ADMIN_PASSWORD': '',
        })
        cls.env.start()
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        cls.m = importlib.import_module('app')
        cls.m.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        cls.m.limiter.enabled = False

    @classmethod
    def tearDownClass(cls):
        with cls.m.app.app_context():
            cls.m.db.session.remove()
            cls.m.db.engine.dispose()
        cls.env.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.ctx = self.m.app.app_context()
        self.ctx.push()
        self.db = self.m.db
        self.db.drop_all()
        self.db.create_all()
        student = self.m.User(username='student', password='unused', is_admin=False)
        admin = self.m.User(username='admin', password='unused', is_admin=True)
        course = self.m.Course(title='Real course', category='Test', price='1000',
                               price_iqd=1000, is_demo=False, is_published=True)
        self.db.session.add_all([student, admin, course])
        self.db.session.flush()
        self.db.session.add(self.m.Lesson(course_id=course.id, title='Lesson', video_url='test.mp4'))
        self.db.session.commit()
        self.student_id, self.admin_id, self.course_id = student.id, admin.id, course.id
        self.client = self.m.app.test_client()

    def tearDown(self):
        self.db.session.remove()
        self.ctx.pop()

    def login(self, uid):
        # Each test keeps an app context; discard Flask-Login's cached user.
        from flask import g
        g.pop('_login_user', None)
        with self.client.session_transaction() as session:
            session['_user_id'] = str(uid)
            session['_fresh'] = True

    def checkout(self):
        row = self.m.CardCheckout(user_id=self.student_id, order_type='course',
                reference_id=self.course_id, amount_iqd=1000,
                gateway_expected_amount_iqd=1250, gateway_invoice_id='invoice-course',
                payment_provider='swiftpay_live', status='pending')
        self.db.session.add(row)
        self.db.session.commit()
        return row

    def webhook(self, amount=1250, event='payment.succeeded', live=True,
                status='SUCCEEDED',
                secret='whsec_test_fixture', timestamp=None, invoice_id='invoice-course'):
        body = json.dumps({'event': event, 'data': {'invoiceId': invoice_id,
            'amount': amount, 'isLive': live, 'status': status,
            'paymentId': 'payment-1'}}).encode()
        timestamp = int(time.time()) if timestamp is None else timestamp
        signature = hmac.new(secret.encode(), str(timestamp).encode() + b'.' + body,
                             hashlib.sha256).hexdigest()
        return self.client.post('/payments/swiftpay/live/webhook', data=body,
                headers={'X-SwiftPay-Signature': f't={timestamp},v1={signature}'},
                content_type='application/json')

    def enrollment(self):
        return self.m.Enrollment.query.filter_by(user_id=self.student_id,
                                                course_id=self.course_id).first()

    def test_signed_card_payment_activates_without_admin_or_browser_return(self):
        checkout = self.checkout()
        self.assertIsNone(self.enrollment())
        self.assertEqual(self.webhook().status_code, 200)  # no Origin/Referer
        self.assertEqual(checkout.status, 'paid')
        self.assertTrue(self.m.enrollment_has_access(self.enrollment()))
        self.assertIsNotNone(self.enrollment().expires_at)
        self.assertEqual(self.m.CoursePayment.query.count(), 0)

    def test_duplicate_success_events_do_not_extend_access_or_notify_twice(self):
        self.checkout()
        self.webhook()
        expiry = self.enrollment().expires_at
        count = self.m.Notification.query.count()
        self.webhook()
        self.webhook(event='invoice.paid')
        self.assertEqual(self.m.Enrollment.query.count(), 1)
        self.assertEqual(self.enrollment().expires_at, expiry)
        self.assertEqual(self.m.Notification.query.count(), count)

    def test_invalid_confirmations_never_unlock_course(self):
        checkout = self.checkout()
        for arguments in ({'amount': 1000}, {'amount': 1250.9}, {'amount': True},
                          {'amount': None}, {'amount': 'NaN'}, {'amount': 'Infinity'},
                          {'live': False}, {'event': 'payment.failed'},
                          {'status': 'PENDING'},
                          {'invoice_id': 'unknown'}, {'invoice_id': 'invoice-course' + 'x' * 121},
                          {'secret': 'wrong'}, {'timestamp': int(time.time()) - 301},
                          {'timestamp': int(time.time()) + 301}):
            with self.subTest(arguments=arguments):
                self.webhook(**arguments)
                self.assertIsNone(self.enrollment())
                self.assertEqual(checkout.status, 'pending')

    def test_admin_and_paid_video_routes_reject_anonymous_and_regular_users(self):
        lesson_id = self.m.Lesson.query.filter_by(course_id=self.course_id).one().id
        self.assertEqual(self.client.get('/admin').status_code, 302)
        self.assertEqual(self.client.get(f'/admin/course/{self.course_id}/lessons').status_code, 302)
        self.assertEqual(self.client.get(f'/protected-video/{lesson_id}').status_code, 403)

        self.login(self.student_id)
        self.assertEqual(self.client.get('/admin').status_code, 403)
        self.assertEqual(self.client.get(f'/admin/course/{self.course_id}/lessons').status_code, 403)
        self.assertEqual(self.client.get(f'/protected-video/{lesson_id}').status_code, 403)

    def test_cloud_video_upload_uses_parallel_multipart_transfer(self):
        video = self.m.FileStorage(stream=BytesIO(b'video-bytes'), filename='lesson.mp4',
                                   content_type='video/mp4')
        with patch.dict(os.environ, {'KORSIK_S3_BUCKET': 'fixture-bucket'}), \
             patch.object(self.m, 'korsik_bucket_enabled', return_value=True), \
             patch.object(self.m, 'korsik_s3', return_value=Mock()) as s3_factory:
            stored = self.m.save_video(video)
            transfer = s3_factory.return_value.upload_fileobj.call_args.kwargs['Config']

        self.assertRegex(stored, r'^s3:videos/[0-9a-f]{32}\.mp4$')
        # Inspect the transfer config instead of timing a real network upload.
        self.assertTrue(transfer.use_threads)
        self.assertEqual(transfer.max_concurrency, 3)

    def test_browser_success_parameter_does_not_activate(self):
        checkout = self.checkout()
        self.login(self.student_id)
        with self.client.session_transaction() as session:
            session['swiftpay_checkout'] = {'order_type': 'course', 'order_id': checkout.id,
                'user_id': self.student_id, 'invoice_id': 'invoice-course'}
        response = self.client.get('/payments/swiftpay/return?result=success')
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.enrollment())
        self.assertEqual(self.client.get('/payments/swiftpay/return/status').json['state'], 'pending')
        self.webhook()
        response = self.client.get('/payments/swiftpay/return')
        self.assertIn('تم تفعيل الكورس تلقائياً'.encode(), response.data)
        self.assertIn(b'href="/learn"', response.data)
        self.assertEqual(self.client.get('/payments/swiftpay/return/status').json['state'], 'paid')

    def test_card_checkout_does_not_activate_until_webhook(self):
        self.login(self.student_id)
        with patch.object(self.m, 'create_swiftpay_invoice',
                          return_value=('invoice-course', 'https://swiftpayiq.com/pay?slug=fixture', 1250)):
            response = self.client.post(f'/course/{self.course_id}/pay-card',
                data={'contact': '07701234567', 'accept_terms': 'yes'},
                headers={'Origin': 'https://localhost'}, base_url='https://localhost')
        self.assertEqual(response.status_code, 303)
        self.assertIsNone(self.enrollment())
        self.assertEqual(self.m.CardCheckout.query.one().status, 'pending')
        self.webhook()
        self.assertTrue(self.m.enrollment_has_access(self.enrollment()))

    def test_manual_payment_waits_for_admin_then_activates(self):
        method = self.m.PaymentMethod(name='Qi Card', is_active=True)
        self.db.session.add(method)
        self.db.session.commit()
        self.login(self.student_id)
        response = self.client.post(f'/course/{self.course_id}/payment',
            data={'payment_method_id': method.id, 'transaction_id': 'manual-transfer'},
            headers={'Origin': 'https://localhost'}, base_url='https://localhost')
        self.assertEqual(response.status_code, 302)
        payment = self.m.CoursePayment.query.one()
        self.assertEqual(payment.status, 'pending')
        self.assertFalse(self.m.enrollment_has_access(self.enrollment()))
        approve_url = f'/admin/payment/{payment.id}/approve'
        self.assertEqual(self.client.post(approve_url, headers={'Origin': 'https://localhost'},
                         base_url='https://localhost').status_code, 403)
        self.login(self.admin_id)
        self.assertEqual(self.client.post(approve_url, headers={'Origin': 'https://localhost'},
                         base_url='https://localhost').status_code, 302)
        self.assertTrue(self.m.enrollment_has_access(self.enrollment()))
        expiry = self.enrollment().expires_at
        self.client.post(approve_url, headers={'Origin': 'https://localhost'}, base_url='https://localhost')
        self.assertEqual(self.enrollment().expires_at, expiry)


if __name__ == '__main__':
    unittest.main()
