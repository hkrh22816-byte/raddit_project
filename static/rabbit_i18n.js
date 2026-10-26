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

  var academyExact={
    "أكاديمية كورسيك":"Korsik Academy",
    "كورسيك":"Korsik",
    "أكاديمية":"Academy",
    "مستقبلك الرقمي يبدأ من":"Your digital future starts with",
    "تعلّم المهارات اللي تحتاجها بخطوات منظّمة. استكشف مسارات التسويق الرقمي والتصميم والبرمجة وصناعة المحتوى، وتابع رحلتك التعليمية على RABBIT.":"Learn practical digital skills through structured paths in digital marketing, design, web development, and content creation. Track your learning journey on RABBIT.",
    "استكشف كورسات كورسيك ←":"Explore Korsik Courses ←",
    "كورساتي ومتابعة التعلّم":"My Courses & Progress",
    "أنشئ حسابك وابدأ":"Create an Account & Start",
    "✦ التسويق الرقمي":"✦ Digital Marketing",
    "✦ التصميم":"✦ Design",
    "✦ تطوير المواقع":"✦ Web Development",
    "✦ صناعة الفيديو":"✦ Video Production",
    "الخدمات والمتجر الرقمي ↓":"Digital Services & Store ↓",
    "ابدأ مهارة جديدة،":"Start learning a new skill,",
    "وابنِ خطوتك الجاية.":"and take your next step.",
    "مسارات تعليمية من كورسيك تساعدك تعرف من وين تبدأ. النماذج التعريفية ومسارات التحضير مو متاحة للشراء إلى أن تُرفع الفيديوهات الحقيقية.":"Explore Korsik learning paths and find where to begin. Preview and upcoming courses are not available for purchase until their real video lessons are published.",
    "عرض جميع الكورسات ←":"View All Courses ←",
    "اختار المجال اللي تحب تتعلمه":"Choose the skill you want to learn",
    "تعرّف على المحاور ومدة الاشتراك":"Review the syllabus and subscription period",
    "ابدأ الدروس المتاحة وتابع تقدمك":"Start available lessons and track your progress",
    "نموذج تعريفي":"Preview Course",
    "متاح للاشتراك":"Available to Enroll",
    "قيد التجهيز":"Coming Soon",
    "محاور":"Modules",
    "للعرض فقط":"Preview Only",
    "تفاصيل المسار":"Explore Course",
    "قريباً: مسارات الأكاديمية. تابع صفحة الكورسات للاطلاع على جديدنا.":"Academy courses are coming soon. Visit the course catalog for updates.",
    "التعلّم بداية الطريق، والتطبيق يصنع الفرق.":"Learning is the first step. Practice makes the difference.",
    "تعلم مع كورسيك، واستفد من خدمات RABBIT ومتجرها لتطوير مشروعك الرقمي.":"Learn with Korsik and use RABBIT services and its store to develop your digital projects.",
    "استكشف الأكاديمية":"Explore the Academy",
    "خدمات تكمّل رحلتك الرقمية":"Services That Support Your Digital Journey",
    "خدمات السوشيال ميديا":"Social Media Services",
    "حلول لإدارة وتنمية الحسابات":"Solutions for managing and growing accounts",
    "وزيادة التفاعل وبناء حضور رقمي":"Increasing engagement and building a stronger",
    "أقوى على منصات التواصل الاجتماعي.":"online presence across social platforms.",
    "تصفح الخدمات ←":"Browse Services ←",
    "المواقع والتطبيقات":"Websites & Applications",
    "تصميم وتطوير المواقع والتطبيقات":"Design and development of websites, applications",
    "والأنظمة الرقمية المخصصة":"and custom digital systems",
    "للأفراد والمشاريع والشركات.":"for individuals, projects, and businesses.",
    "ابدأ مشروعك ←":"Start Your Project ←",
    "خدمات الحسابات":"Account Services",
    "خدمات إدارة وتأمين الحسابات":"Account management and security services",
    "والمساعدة في استرجاع الحسابات":"with assistance recovering disabled",
    "المعطلة أو المخترقة.":"or compromised accounts.",
    "ادخل المتجر ←":"Visit the Store ←",
    "مساحة تعليمية من RABBIT لتحوّل المهارات الرقمية إلى خطوات عملية.":"A learning experience by RABBIT that turns digital skills into practical steps.",
    "ابدأ من الأساس، تعلّم بطريقتك، وطبّق على مشروع حقيقي.":"Start with the fundamentals, learn at your own pace, and apply your skills to real projects.",
    "مسارات في التسويق الإلكتروني، التصميم، البرمجة وصناعة الفيديو.":"Learning paths in marketing, design, programming, and video production.",
    "النماذج التجريبية للعرض فقط، والاشتراك يفتح عند توفر الدروس الفعلية.":"Demo courses are for preview only. Enrollment opens when actual lessons become available.",
    "استكشف مسارات كورسيك":"Explore Korsik Paths",
    "بحث":"Search",
    "الكل":"All",
    "نموذج تجريبي — للعرض فقط":"Demo Course — Preview Only",
    "تفاصيل هذا الكورس":"Course Details",
    "ستتوفر قريباً.":"Coming soon.",
    "نموذج للعرض فقط":"Preview Only",
    "قريباً — بانتظار الدروس":"Coming Soon — Lessons in Preparation",
    "عرض الدورة":"View Course",
    "لا توجد دورات مطابقة":"No Matching Courses",
    "لعملية البحث حالياً.":"for your current search.",
    "خروج":"Log out",
    "← العودة إلى الكورسات":"← Back to Courses",
    "اشتراك أكاديمية كورسيك بالبطاقة":"Korsik Academy — Card Subscription",
    "رقم الهاتف العراقي لإصدار الفاتورة":"Iraqi phone number for invoicing",
    "أوافق على شروط الشراء":"I agree to the purchase terms",
    "هذا كورس تجريبي للعرض فقط":"This is a preview course",
    "المحاور التالية للتوضيح وليس بها فيديوهات تدريب مكتملة. لن يتم تحصيل أي مبلغ حتى نرفع الكورس الحقيقي ونفتح التسجيل.":"The following modules are illustrative and do not contain complete training videos. No payments are collected until real lessons are uploaded and enrollment opens.",
    "اشتراكك في هذه الدورة مفعّل. يمكنك الآن مشاهدة جميع الدروس المتاحة.":"Your course subscription is active. You can now access the available lessons.",
    "الرجوع إلى كورساتي":"Back to My Courses",
    "نموذج تجريبي — الاشتراك غير متاح حالياً.":"Preview course — enrollment is not currently available.",
    "الكورس قيد التجهيز، وسيُفتح الاشتراك عند نشر دروس الفيديو الحقيقية.":"This course is being prepared. Enrollment will open once its real video lessons are published.",
    "تم استلام طلب اشتراكك.":"Your enrollment request has been received.",
    "بعد تأكيد الدفع ومراجعة الطلب":"After payment confirmation and order review,",
    "سيتم فتح جميع فيديوهات هذه الدورة لحسابك.":"all course videos will be unlocked for your account.",
    "هذه الدورة تحتاج إلى اشتراك.":"A subscription is required for this course.",
    "بعد إتمام الدفع أرسل طلب الاشتراك،":"Complete payment and submit your enrollment request,",
    "وبعد مراجعة الطلب سيتم فتح الدورة لحسابك.":"and your course will be unlocked after the request is reviewed.",
    "طلب الاشتراك في الدورة":"Request Course Enrollment",
    "يجب تسجيل الدخول أو إنشاء حساب":"You need to log in or create an account",
    "حتى تتمكن من طلب الاشتراك في هذه الدورة.":"to request enrollment in this course.",
    "تسجيل الدخول / إنشاء حساب":"Log In / Create Account",
    "محتوى الدورة":"Course Content",
    "متصفحك لا يدعم تشغيل الفيديو.":"Your browser does not support video playback.",
    "مشاهدة الفيديو":"Watch Video",
    "لا يوجد فيديو لهذا الدرس حالياً.":"There is no video for this lesson yet.",
    "هذا الدرس متاح للمشتركين":"This lesson is available to subscribers",
    "في هذه الدورة فقط.":"of this course only.",
    "طلب اشتراكك بانتظار التفعيل.":"Your enrollment request is awaiting activation.",
    "اشترك في هذه الدورة":"Subscribe to this course",
    "لفتح الفيديو.":"to unlock the video.",
    "سجل الدخول ثم اطلب الاشتراك":"Log in and request enrollment",
    "للوصول إلى هذا الدرس.":"to access this lesson.",
    "الدروس ستُضاف قريباً.":"Lessons are coming soon.",
    "أكاديمية كورسيك — إدارة الكورسات":"Korsik Academy — Course Management",
    "حالة الدفع":"Payment Status",
    "الرصيد":"Balance",
    "منطقة الدراسة":"Learning Hub",
    "إعلانات Meta من الصفر إلى الاحتراف":"Meta Ads: From Beginner to Advanced",
    "إعلانات ميتا من الصفر إلى الاحتراف":"Meta Ads: From Beginner to Advanced",
    "تصميم السوشيال ميديا":"Social Media Design",
    "تصميم محتوى السوشيال ميديا":"Social Media Content Design",
    "إنشاء المواقع":"Website Development",
    "مونتاج الريلز":"Reels Video Editing"
  };
  Object.keys(academyExact).forEach(function(key){exact[key]=academyExact[key];});

  var courseContentEnglish={
    "مبتدئ":"Beginner",
    "متوسط":"Intermediate",
    "متقدم":"Advanced",
    "التسويق":"Marketing",
    "التسويق الرقمي":"Digital Marketing",
    "التصميم":"Design",
    "السوشيال ميديا":"Social Media",
    "البرمجة":"Programming",
    "البرمجة والمواقع":"Programming & Websites",
    "صناعة الفيديو":"Video Production",
    "الذكاء الاصطناعي":"Artificial Intelligence",
    "الأعمال":"Business",
    "المهارات المكتبية":"Office Skills",
    "اللغات":"Languages",
    "فريق أكاديمية كورسيك — نموذج":"Korsik Academy Team — Demo",
    "نموذج تجريبي | إعلانات ميتا من الصفر إلى أول حملة":"Demo | Meta Ads: From Zero to Your First Campaign",
    "نموذج تجريبي | تصميم محتوى السوشيال ميديا للمشاريع":"Demo | Social Media Content Design for Businesses",
    "نموذج تجريبي | إنشاء موقع تجاري متكامل":"Demo | Building a Complete Business Website",
    "نموذج تجريبي | مونتاج ريلز احترافي":"Demo | Professional Reels Editing",
    "من إعداد الصفحة والحساب الإعلاني إلى اختيار الجمهور وتحسين النتائج.":"From setting up your page and ad account to targeting audiences and improving campaign performance.",
    "أساسيات الهوية البصرية وتصميم المنشورات وتخطيط المحتوى.":"Visual identity fundamentals, social media post design, and content planning.",
    "تخطيط صفحات الموقع وتجربة المستخدم والنشر والأمان.":"Website structure, user experience, publishing, and security.",
    "كتابة فكرة الفيديو وتنظيم اللقطات والمونتاج والتصدير.":"Developing the video concept, organizing clips, editing, and exporting.",
    "هذا نموذج تعريفي غير متاح للشراء. الدروس الحقيقية ستضاف لاحقاً.":"This is a non-purchasable demo. Real lessons will be added later.",
    "إنشاء الحساب الإعلاني":"Create an Ad Account",
    "تحديد الجمهور والميزانية":"Choose Audiences and Budget",
    "تحسين النتائج":"Optimize Results",
    "الهوية البصرية":"Visual Identity",
    "تصميم المنشورات":"Social Media Post Design",
    "خطة المحتوى":"Content Plan",
    "هيكلة الموقع":"Website Structure",
    "النماذج وصفحات الخدمات":"Forms and Service Pages",
    "النشر والأمان":"Publishing and Security",
    "هوك الفيديو":"Video Hook",
    "المونتاج والترجمة":"Editing and Captions",
    "التصدير للنشر":"Export for Publishing",
    "إعلانات TikTok والتسويق عبر تيك توك":"TikTok Ads and Marketing",
    "إدارة صفحات السوشيال ميديا":"Social Media Page Management",
    "صناعة المحتوى بالموبايل":"Mobile Content Creation",
    "مونتاج CapCut من الصفر إلى الاحتراف":"CapCut Editing: Beginner to Advanced",
    "التصميم باستخدام Canva":"Design with Canva",
    "Photoshop من الصفر":"Photoshop Fundamentals",
    "الذكاء الاصطناعي للعمل والدراسة":"AI for Work and Study",
    "ChatGPT لصناعة المحتوى والتسويق":"ChatGPT for Content and Marketing",
    "إنشاء متجر إلكتروني":"Building an Online Store",
    "كيف تبدأ مشروع بيع أونلاين في العراق":"How to Start an Online Business in Iraq",
    "التصوير الإعلاني بالموبايل":"Mobile Product Photography",
    "التعليق الصوتي وصناعة الفيديو":"Voiceover and Video Production",
    "Excel من الصفر للعمل":"Excel for Work: From Scratch",
    "المحاسبة لأصحاب المشاريع الصغيرة":"Accounting for Small Business Owners",
    "اللغة الإنجليزية للعمل والمحادثة":"English for Work and Conversation",
    "تعلم كيفية إطلاق حملات إعلانية ناجحة على فيسبوك وإنستغرام.":"Learn to launch successful Facebook and Instagram advertising campaigns.",
    "تعلم بناء الحملات الإعلانية وقراءة النتائج وتحسينها.":"Learn to build, measure, and optimize advertising campaigns.",
    "تنظيم وإدارة الحسابات التجارية وجدولة المحتوى باحترافية.":"Organize and manage business accounts and schedule content professionally.",
    "تصوير وإنتاج محتوى مرئي جذاب باستخدام الهاتف.":"Create engaging visual content using your phone.",
    "مونتاج الفيديوهات القصيرة والريلز خطوة بخطوة.":"Edit short-form videos and reels step by step.",
    "تصميم الإعلانات والمنشورات والهويات البصرية بسهولة.":"Design ads, posts, and visual identities with ease.",
    "أساسيات التعديل والدمج وبناء التصاميم الإعلانية.":"Fundamentals of photo editing, compositing, and advertising design.",
    "استخدام أدوات الذكاء الاصطناعي لرفع الإنتاجية.":"Use AI tools to improve productivity.",
    "استخدام ChatGPT للأفكار والسيناريوهات والخطط التسويقية.":"Use ChatGPT for ideas, scripts, and marketing plans.",
    "بناء متجر إلكتروني واستقبال طلبات الزبائن.":"Build an online store and accept customer orders.",
    "من اختيار المنتج إلى التسويق والتوصيل داخل العراق.":"From product selection to marketing and delivery across Iraq.",
    "زوايا وإضاءة تصوير المنتجات بالموبايل.":"Product photography angles and lighting with a phone.",
    "تسجيل صوت واضح وإنتاج فيديو احترافي.":"Record clear audio and produce professional videos.",
    "الجداول والمعادلات والتقارير التي يحتاجها الموظف.":"Spreadsheets, formulas, and workplace reports.",
    "فهم الأرباح والخسائر والمصاريف وإدارة المشروع.":"Understand profits, losses, expenses, and project management.",
    "محادثات ومصطلحات عملية للاستخدام في بيئة العمل.":"Practical conversations and vocabulary for the workplace."
  };
  Object.keys(courseContentEnglish).forEach(function(key){exact[key]=courseContentEnglish[key];});

  var titleMap={
    'الخدمات | RABBIT':'Services | RABBIT','المتجر | RABBIT':'Store | RABBIT','سلة التسوق | RABBIT':'Shopping Cart | RABBIT',
    'أكاديمية كورسيك | تعلم المهارات الرقمية على RABBIT':'Korsik Academy | Learn Digital Skills on RABBIT',
    'أكاديمية كورسيك | RABBIT':'Korsik Academy | RABBIT',
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
    if((m=text.match(/^أهلاً\s+(.+?)،\s*اختار مهارتك الجاية\.?$/))) return 'Welcome '+m[1]+', choose your next skill.';
    if((m=text.match(/^المحور\s+(\d+):\s*(.+)$/))) return 'Module '+m[1]+': '+(exact[m[2]] || m[2]);
    if((m=text.match(/^([\d,]+)\s+محاور?$/))) return m[1]+' modules';
    if((m=text.match(/^([\d,]+)\s+د\.ع\s*\/\s*([\d,]+)\s+يوم$/))) return m[1]+' IQD / '+m[2]+' days';
    if((m=text.match(/^([\d,]+)\s+د\.ع\s+بال(بطاقة|بطاقه)$/))) return m[1]+' IQD by card';
    if((m=text.match(/^شراء من رصيد Rabbit\s*[—-]\s*([\d,]+)\s+د\.ع$/))) return 'Pay with Rabbit Wallet — '+m[1]+' IQD';
    if((m=text.match(/^اشتراك لمدة\s+([\d,]+)\s+يوم\.\s*(.+)$/))) return 'Subscription for '+m[1]+' days. Pay securely by card; your access starts after payment confirmation. Renewal is available when your access expires. Do not enter card details on RABBIT.';
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
        list.forEach(function(m){
          if(m.type==='characterData'){
            translateTextNode(m.target);
          }else{
            m.addedNodes.forEach(function(n){if(n.nodeType===Node.TEXT_NODE) translateTextNode(n);else if(n.nodeType===1) walk(n);});
          }
        });
      });
      observer.observe(document.body,{childList:true,characterData:true,subtree:true});
    }
  });
})();