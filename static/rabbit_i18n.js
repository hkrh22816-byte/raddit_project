(function(){
  'use strict';

  var STORAGE_KEY='rabbit_lang';
  var lang=localStorage.getItem(STORAGE_KEY)==='en'?'en':'ar';

  var exact={
    'الرئيسية':'Home','الخدمات':'Services','المتجر':'Store','الكورسات':'Courses','الدعم':'Support','قريباً':'Soon',
    'تسجيل الدخول':'Log in','إنشاء حساب':'Create account','حسابي':'My Account','الإدارة':'Admin','السلة':'Cart','الإشعارات':'Notifications',
    'إجازة مزاولة مهنة':'Licensed business','منتسب إلى غرفة تجارة بغداد':'Baghdad Chamber of Commerce member',
    'بوابة الدفع':'Payment gateway','القاصّة — مرخصة من البنك المركزي العراقي':'Al-Qasa — licensed by the Central Bank of Iraq',
    'موافقة هيئة الإعلام والاتصالات':'Media & Communications Commission approval','✦ الدعم السريع':'✦ Quick support',

    'أهلاً':'Welcome','تصفح الخدمات':'Browse services','تصفح المتجر':'Browse store',
    'حسابك متصل الآن بمنصة RABBIT. تصفح خدماتنا الرقمية واختر ما يناسب مشروعك، أو استكشف المنتجات المتاحة في المتجر.':'Your account is connected to RABBIT. Browse our digital services and choose what fits your project, or explore available products in the store.',
    'اختار':'Choose','نوع الخدمة':'service category',
    'رتبنا الخدمات على شكل أقسام. تدخل للقسم المطلوب، تختار الخدمة المناسبة، تشوف السعر والتفاصيل وتكمل الطلب.':'Services are organized into clear categories. Open the category you need, choose a service, review the price and details, then complete your order.',
    'عرض خدمات القسم':'View category services','الخدمات قيد التجهيز':'Services are being prepared',
    'الخدمات الرقمية':'Digital services','خدمات رقمية':'Digital services','خدمة':'Service','خدمة متاحة':'service available','خدمات متاحة':'services available',

    'المتجر الرقمي.':'Digital Store.','الرقمي.':'Digital.',
    'العروض والمنتجات والحسابات المتاحة بمكان واحد. توفر العروض يتغير حسب المخزون وشروط المنصة.':'Offers, products and available accounts in one place. Availability may change based on stock and platform terms.',
    'متوفر حالياً':'Available now','غير متوفر حالياً':'Currently unavailable','التفاصيل والشراء':'Details & Buy','منتج من المتجر':'Store product',
    'السعر غير محدد حالياً. تواصل ويانا قبل الشراء.':'The price is not set yet. Contact us before purchasing.',
    'هذا المنتج غير متاح حالياً.':'This product is currently unavailable.',
    '🛒 أضف للسلة':'🛒 Add to cart','أضف للسلة':'Add to cart','شراء الآن':'Buy now',
    'اختار طريقة الدفع':'Choose payment method','اختار طريقة الدفع أولاً.':'Choose your payment method first.',
    'نفس ترتيب الخدمات: اختار طريقتك أولاً، وبعدها تظهر الحقول المطلوبة فقط.':'Choose your payment method first, then only the required fields will appear.',
    '💚 محفظة Rabbit':'💚 Rabbit Wallet','محفظة Rabbit':'Rabbit Wallet','خصم مباشر من رصيدك':'Instant deduction from your balance',
    '💳 دفع يدوي':'💳 Manual payment','دفع يدوي':'Manual payment','كي كارد أو زين كاش':'Qi Card or Zain Cash',
    'رصيدك الحالي:':'Current balance:','الكمية':'Quantity','رقم التواصل':'Contact number','ملاحظات الطلب (اختياري)':'Order notes (optional)',
    'الدفع من المحفظة':'Pay with wallet','طريقة الدفع':'Payment method','اختر الطريقة':'Choose a method','الاسم:':'Name:',
    'رقم العملية / التحويل':'Transaction / transfer number','حساب استرجاع المبلغ':'Refund account','إثبات الدفع':'Payment proof',
    'إثبات التحويل':'Payment proof','إرسال الطلب ومراجعة الدفع':'Submit order for payment review','الدفع اليدوي غير متاح حالياً.':'Manual payment is currently unavailable.',
    'سجل الدخول حتى تشتري':'Log in to purchase',

    'سلة التسوق 🛒':'Shopping Cart 🛒','سلة التسوق':'Shopping Cart',
    'راجع العناصر، وبعدها اختار طريقة الدفع. الحقول ما تظهر إلا حسب الطريقة اللي تختارها.':'Review your items, then choose a payment method. Only the fields required for that method will appear.',
    'إتمام الشراء':'Checkout','بيانات الطلب':'Order details','بيانات الطلب والتحويل':'Order & transfer details',
    'رابط الحساب أو المشروع':'Account or project link','ملاحظات (اختياري)':'Notes (optional)','ملاحظات المنتج':'Product notes',
    'أوافق على شروط الشراء وسياسة الطلب والاسترجاع':'I agree to the purchase terms, order policy and refund policy',
    'المجموع':'Total','حذف':'Remove','حذف العنصر':'Remove item',
    'سلتك فارغة':'Your cart is empty','أضف خدمة أو منتج وبعدها ارجع كمل الشراء.':'Add a service or product, then return here to complete your purchase.',

    'شحن المحفظة':'Top up wallet','شحن رصيد المحفظة':'Top up wallet balance','الرصيد الحالي':'Current balance','الطلبات':'Orders','طلباتي':'My Orders',
    'طلبات الخدمات':'Service orders','طلبات المتجر':'Store orders','طلب خدمة':'Service order','طلب متجر':'Store order',
    'قيد المراجعة':'Under review','بانتظار المراجعة':'Pending review','قيد التنفيذ':'In progress','مكتمل':'Completed','ملغي':'Cancelled','مرفوض':'Rejected',
    'تسجيل الخروج':'Log out','العودة للرئيسية':'Back to Home','العودة':'Back',

    'مركز الدعم':'Support Center','الدعم الفني':'Technical Support','فتح تذكرة':'Open ticket','تذكرة جديدة':'New ticket','الموضوع':'Subject','القسم':'Category',
    'الرسالة':'Message','إرسال':'Send','إرسال الرسالة':'Send message','تذاكر الدعم':'Support tickets','لا توجد تذاكر حالياً.':'No tickets yet.',
    'استفسار عام':'General inquiry','مشكلة في الطلب':'Order issue','مشكلة في الدفع':'Payment issue','مشكلة تقنية':'Technical issue',

    'دخول أسرع.':'Faster access.','حساب أوضح.':'A clearer account.',
    'استخدم اسم المستخدم أو البريد أو رقم الهاتف للدخول. إنشاء الحساب الجديد والتحقق منه متاحان حالياً عبر البريد الإلكتروني.':'Use your username, email or phone number to sign in. New account registration and verification are currently available by email.',
    'خانة واحدة تكفي: اليوزر أو الإيميل أو رقم الهاتف.':'One field is enough: username, email or phone number.',
    'اسم المستخدم / الإيميل / رقم الهاتف':'Username / email / phone number','كلمة المرور':'Password','إظهار كلمة المرور':'Show password',
    'دخول إلى RABBIT':'Enter RABBIT','نسيت كلمة المرور؟':'Forgot password?','البريد الإلكتروني':'Email','رقم الهاتف':'Phone number','رقم الهاتف العراقي':'Iraqi phone number',
    'أدخل بريدك الإلكتروني لنرسل إليه رمز التحقق قبل إنشاء الحساب.':'Enter your email and we will send a verification code before creating your account.',
    'إرسال رمز التحقق':'Send verification code','تأكيد الرمز':'Verify code','أدخل الرمز المكوّن من 6 أرقام. ينتقل المؤشر تلقائياً بين الخانات.':'Enter the 6-digit code. The cursor moves automatically between fields.',
    'تغيير البريد':'Change email','آخر خطوة':'Final step','تم التحقق. اختر اسم مستخدم وكلمة مرور لحسابك.':'Verified. Choose a username and password for your account.',
    'اسم المستخدم':'Username','إنشاء الحساب والدخول':'Create account & sign in','تأكيد كلمة المرور':'Confirm password',

    'الكورسات التعليمية':'Courses','كورسات':'Courses','الكورسات قيد التجهيز':'Courses are being prepared','ابدأ التعلم':'Start learning','مشاهدة الكورس':'View course',
    'العودة للكورسات':'Back to courses','منطقة الدراسة':'Learning Hub','اشترِ الآن':'Buy now','شراء الكورس':'Buy course',

    'موافق':'Agree','حفظ':'Save','تأكيد':'Confirm','إلغاء':'Cancel','استمرار':'Continue','التالي':'Next','السابق':'Previous',
    'تفاصيل':'Details','تفاصيل الطلب':'Order details','التاريخ':'Date','الحالة':'Status','السعر':'Price','رقم الطلب':'Order ID'
  };

  var titleMap={
    'الخدمات | RABBIT':'Services | RABBIT','المتجر | RABBIT':'Store | RABBIT','سلة التسوق | RABBIT':'Shopping Cart | RABBIT',
    'حسابي | RABBIT':'My Account | RABBIT','الدعم | RABBIT':'Support | RABBIT','الإشعارات | RABBIT':'Notifications | RABBIT'
  };

  function clean(text){return (text||'').trim().replace(/\s+/g,' ');}

  function translateDynamic(text){
    var m;
    if((m=text.match(/^(\d+)\s+خدمة متاحة$/))) return m[1]+' services available';
    if((m=text.match(/^الرصيد\s+(.+)$/))) return 'Balance '+m[1];
    if((m=text.match(/^الرصيد:\s*(.+)$/))) return 'Balance: '+m[1];
    if((m=text.match(/^رصيدك الحالي:\s*(.+)$/))) return 'Current balance: '+m[1];
    if((m=text.match(/^السلة\s*\((\d+)\)$/))) return 'Cart ('+m[1]+')';
    if((m=text.match(/^الدفع من المحفظة\s*[—-]\s*(.+)$/))) return 'Pay with wallet — '+m[1];
    if((m=text.match(/^رقم\s+(\d+)$/))) return 'Digit '+m[1];
    return null;
  }

  function translateTextNode(node){
    if(!node || !node.nodeValue) return;
    var raw=node.nodeValue;
    var normalized=clean(raw);
    if(!normalized) return;
    var translated=exact[normalized] || translateDynamic(normalized);
    if(!translated) return;
    var lead=raw.match(/^\s*/)[0], tail=raw.match(/\s*$/)[0];
    node.nodeValue=lead+translated+tail;
  }

  function translateElement(el){
    if(!el || el.nodeType!==1) return;
    var tag=el.tagName;
    if(tag==='SCRIPT'||tag==='STYLE'||tag==='CODE'||tag==='PRE') return;
    ['placeholder','title','aria-label','value'].forEach(function(attr){
      if(!el.hasAttribute(attr)) return;
      if(attr==='value' && !/^(BUTTON|SUBMIT|RESET)$/.test((el.getAttribute('type')||'').toUpperCase())) return;
      var v=clean(el.getAttribute(attr));
      if(exact[v]) el.setAttribute(attr,exact[v]);
      else { var d=translateDynamic(v); if(d) el.setAttribute(attr,d); }
    });
  }

  function walk(root){
    if(lang!=='en' || !root) return;
    var walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT|NodeFilter.SHOW_ELEMENT);
    var n;
    while((n=walker.nextNode())){
      if(n.nodeType===Node.TEXT_NODE){
        var p=n.parentElement;
        if(p && !/^(SCRIPT|STYLE|CODE|PRE)$/.test(p.tagName)) translateTextNode(n);
      }else translateElement(n);
    }
  }

  function apply(){
    document.documentElement.lang=lang;
    document.documentElement.dir=lang==='en'?'ltr':'rtl';
    if(document.body) document.body.dir=lang==='en'?'ltr':'rtl';
    if(lang==='en'){
      if(titleMap[document.title]) document.title=titleMap[document.title];
      walk(document.body);
    }
    var btn=document.getElementById('rabbitLangToggle');
    if(btn){
      btn.textContent=lang==='en'?'AR':'EN';
      btn.setAttribute('aria-label',lang==='en'?'Switch to Arabic':'التبديل إلى الإنجليزية');
      btn.title=lang==='en'?'العربية':'English';
    }
  }

  function ensureFallbackButton(){
    if(document.getElementById('rabbitLangToggle')) return;
    var b=document.createElement('button');
    b.id='rabbitLangToggle'; b.type='button'; b.className='rabbit-lang-fallback';
    b.style.cssText='position:fixed;top:14px;right:14px;z-index:12000;border:1px solid rgba(0,245,138,.45);background:#07110c;color:#00f58a;border-radius:10px;padding:9px 12px;font:800 12px Segoe UI,Tahoma,Arial,sans-serif;cursor:pointer;box-shadow:0 6px 22px rgba(0,0,0,.3)';
    document.body.appendChild(b);
  }

  window.RabbitI18n={
    get:function(){return lang;},
    set:function(next){next=next==='en'?'en':'ar';localStorage.setItem(STORAGE_KEY,next);location.reload();},
    toggle:function(){this.set(lang==='en'?'ar':'en');}
  };

  document.addEventListener('DOMContentLoaded',function(){
    ensureFallbackButton();
    var btn=document.getElementById('rabbitLangToggle');
    if(btn) btn.addEventListener('click',function(){window.RabbitI18n.toggle();});
    apply();
    if(lang==='en'){
      var observer=new MutationObserver(function(list){
        list.forEach(function(m){m.addedNodes.forEach(function(n){if(n.nodeType===Node.TEXT_NODE) translateTextNode(n);else if(n.nodeType===1) walk(n);});});
      });
      observer.observe(document.body,{childList:true,subtree:true});
    }
  });
})();