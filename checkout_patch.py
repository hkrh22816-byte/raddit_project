from flask import request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from sqlalchemy import text as sql_text

from app import (
    app, db, limiter,
    CartItem, Service, StoreItem, ServiceOrder, StoreOrder, WalletTransaction,
    cart_entry, wallet_balance_iqd, parse_iqd_price,
    is_account_recovery_service, notify_user, notify_admins, terms_accepted,
)


def _lock_wallet_user():
    db.session.execute(
        sql_text('SELECT id FROM "user" WHERE id = :uid FOR UPDATE'),
        {'uid': current_user.id},
    )


@login_required
@limiter.limit('10 per hour')
def store_buy_wallet_override(item_id):
    item = db.session.get(StoreItem, item_id) or abort(404)
    if not item.is_active or item.stock_status != 'available':
        abort(404)

    unit_price = item.price_iqd or parse_iqd_price(item.price)
    if not unit_price or unit_price < 1:
        flash('السعر غير محدد حالياً.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))

    try:
        quantity = min(99, max(1, int(request.form.get('quantity') or 1)))
    except (TypeError, ValueError):
        quantity = 1

    contact = (request.form.get('contact') or '').strip()
    details = (request.form.get('details') or '').strip()
    if not contact or len(contact) > 80 or len(details) > 2000:
        flash('أدخل رقم تواصل صحيح وتأكد من طول الملاحظات.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))

    total_iqd = unit_price * quantity
    _lock_wallet_user()
    if wallet_balance_iqd(current_user.id) < total_iqd:
        db.session.rollback()
        flash('رصيدك ما يكفي. اشحن المحفظة وبعدها جرّب مرة ثانية.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))

    quantity_note = f'الكمية: {quantity}\n' if quantity > 1 else ''
    order = StoreOrder(
        user_id=current_user.id,
        store_item_id=item.id,
        payment_method_id=None,
        amount_iqd=total_iqd,
        status='pending',
        contact=contact,
        details=(quantity_note + details).strip(),
        transaction_id='RABBIT WALLET',
        refund_account='رصيد Rabbit',
        proof_filename='',
        payment_provider='wallet',
    )
    db.session.add(order)
    db.session.flush()
    db.session.add(WalletTransaction(
        user_id=current_user.id,
        transaction_type='purchase',
        amount_iqd=-total_iqd,
        reference_type='store_order',
        reference_id=order.id,
        note=f'شراء من المتجر بالمحفظة: {item.title}'[:250],
    ))
    notify_user(
        current_user.id,
        'تم استلام طلب المتجر',
        f'انخصم {total_iqd:,} د.ع من محفظتك لطلب «{item.title}».',
        url_for('account'),
    )
    notify_admins(
        'طلب متجر مدفوع من المحفظة',
        f'{current_user.username}: {item.title} · {total_iqd:,} د.ع',
        url_for('admin_store_orders'),
    )
    db.session.commit()
    flash('تم الدفع من محفظة Rabbit واستلام طلبك.', 'success')
    return redirect(url_for('account'))


# Keep the original app route/endpoint, but replace only its view implementation.
app.view_functions['store_buy_wallet'] = store_buy_wallet_override


@login_required
@limiter.limit('10 per hour')
def cart_checkout_wallet():
    rows = CartItem.query.filter_by(user_id=current_user.id).order_by(CartItem.id.asc()).all()
    entries = [(row, cart_entry(row)) for row in rows]

    if not entries or any(data is None for _, data in entries):
        flash('أحد عناصر السلة لم يعد متاحاً أو تغير سعره. راجع السلة.', 'error')
        return redirect(url_for('cart'))

    if not terms_accepted():
        flash('وافق على شروط الشراء وسياسة الطلب قبل الدفع.', 'error')
        return redirect(url_for('cart'))

    contact = (request.form.get('contact') or '').strip()
    if not contact or len(contact) > 80:
        flash('أدخل رقم تواصل صحيح.', 'error')
        return redirect(url_for('cart'))

    validated = []
    total_iqd = 0
    for row, data in entries:
        details = (request.form.get(f'details_{row.id}') or '').strip()
        if len(details) > 2000:
            flash('ملاحظات أحد العناصر أطول من الحد المسموح.', 'error')
            return redirect(url_for('cart'))

        if data['type'] == 'service':
            service = db.session.get(Service, row.service_id)
            if is_account_recovery_service(service):
                flash('خدمة استعادة الحساب تُشترى مباشرة حتى ترفق صورة الحالة.', 'error')
                return redirect(url_for('cart'))
            page_url = (request.form.get(f'page_url_{row.id}') or '').strip()
            if not page_url or len(page_url) > 1000:
                flash('أضف رابط الحساب أو المشروع لكل خدمة.', 'error')
                return redirect(url_for('cart'))
            validated.append((row, data, details, page_url))
        else:
            validated.append((row, data, details, ''))
        total_iqd += int(data['line_total'])

    if total_iqd < 1:
        flash('مجموع السلة غير صحيح.', 'error')
        return redirect(url_for('cart'))

    _lock_wallet_user()
    if wallet_balance_iqd(current_user.id) < total_iqd:
        db.session.rollback()
        flash(f'رصيدك غير كافٍ. مجموع السلة {total_iqd:,} د.ع.', 'error')
        return redirect(url_for('cart'))

    created_count = 0
    service_count = 0
    store_count = 0
    for row, data, details, page_url in validated:
        line_total = int(data['line_total'])
        if data['type'] == 'service':
            if data.get('platform'):
                quantity_line = (
                    f"المطلوب: {data['package_quantity']:,} {data['package_unit']}\n"
                    if data.get('package_quantity') else ''
                )
                group_line = f"نوع الخدمة: {data['package_group']}\n" if data.get('package_group') else ''
                details = f"المنصة: {data['platform']}\n{group_line}{quantity_line}{details}".strip()

            order = ServiceOrder(
                user_id=current_user.id,
                service_id=row.service_id,
                payment_method_id=None,
                service_package_id=row.package_id,
                package_label=data.get('label') or '',
                amount=f"{line_total:,} د.ع",
                page_url=page_url,
                details=details,
                contact=contact,
                refund_account='رصيد Rabbit',
                transaction_id='RABBIT WALLET',
                proof_filename='',
                status='pending',
            )
            db.session.add(order)
            db.session.flush()
            db.session.add(WalletTransaction(
                user_id=current_user.id,
                transaction_type='purchase',
                amount_iqd=-line_total,
                reference_type='service_order',
                reference_id=order.id,
                note=f"شراء خدمة من السلة بالمحفظة: {data['title']}"[:250],
            ))
            service_count += 1
        else:
            quantity = int(data.get('quantity') or 1)
            quantity_note = f"الكمية: {quantity}\n" if quantity > 1 else ''
            order = StoreOrder(
                user_id=current_user.id,
                store_item_id=row.store_item_id,
                payment_method_id=None,
                amount_iqd=line_total,
                status='pending',
                contact=contact,
                details=(quantity_note + details).strip(),
                transaction_id='RABBIT WALLET',
                refund_account='رصيد Rabbit',
                proof_filename='',
                payment_provider='wallet',
            )
            db.session.add(order)
            db.session.flush()
            db.session.add(WalletTransaction(
                user_id=current_user.id,
                transaction_type='purchase',
                amount_iqd=-line_total,
                reference_type='store_order',
                reference_id=order.id,
                note=f"شراء منتج من السلة بالمحفظة: {data['title']}"[:250],
            ))
            store_count += 1

        db.session.delete(row)
        created_count += 1

    notify_user(
        current_user.id,
        'تم الدفع من محفظة Rabbit',
        f'تم خصم {total_iqd:,} د.ع واستلام {created_count} طلبات من السلة.',
        url_for('account'),
    )
    if service_count:
        notify_admins(
            'طلبات خدمات مدفوعة من المحفظة',
            f'{current_user.username}: {service_count} خدمات من السلة',
            url_for('admin_service_orders'),
        )
    if store_count:
        notify_admins(
            'طلبات متجر مدفوعة من المحفظة',
            f'{current_user.username}: {store_count} منتجات من السلة',
            url_for('admin_store_orders'),
        )

    db.session.commit()
    flash('تم الدفع من المحفظة واستلام كل طلبات السلة بنجاح.', 'success')
    return redirect(url_for('account'))


# Register this endpoint once; app.py does not define it.
if 'cart_checkout_wallet' not in app.view_functions:
    app.add_url_rule(
        '/cart/checkout-wallet',
        endpoint='cart_checkout_wallet',
        view_func=cart_checkout_wallet,
        methods=['POST'],
    )
