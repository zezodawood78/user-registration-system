# user-registration-system
# User Registration System with Admin Panel

ده مشروع عملته باستخدام بايثون وبيسمح للمستخدمين بالتسجيل وتسجيل الدخول وكمان فيه لوحة إدارة (Admin Panel) علشان مديري النظام يقدروا يشوفوا ويديروا بيانات المستخدمين

# فكره المشروع :
فكرت ان انا اعمل المشروع ده علشان أتعلم أكتر عن كيفية بناء أنظمة التسجيل وتسجيل الدخول وكيفية التعامل مع الواجهات الرسومية في بايثون باستخدام مكتبة Tkinter كنت عايز أعمل حاجة بسيطة تكون مفيدة في نفس الوقت بيكون فيها شوية أمان في التعامل مع كلمات المرور والبيانات

#ودي المميزات بتاعته :
- **التسجيل**: المستخدمين يقدروا يسجلوا بحسابات جديدة
- **تسجيل الدخول**: أي حد سجل قبل كده يقدر يدخل بحسابه
- **لوحة الإدارة (Admin Panel)**: لو كان عندك صلاحيات إدارية تقدر تشوف كل المستخدمين وتدير حساباتهم
- **تشفير كلمات المرور**: استخدمت تقنيات بسيطة علشان أخزن كلمات المرور بشكل آمن

## التقنيات المستخدمة:
- **بايثون 3**: اللغة الرئيسية
- **Tkinter**: لبناء الواجهة الرسومية (GUI)
- **SQLite**: قاعدة بيانات خفيفة لتخزين بيانات المستخدمين بشكل محلي

## ازاي تشغل المشروع:
1. أول حاجة لازم تعمل **Clone** للمستودع ( تحمله يعني ):
bash
   git clone https://github.com/your-username/user-registration-system.git

   2 عشان نشغله بقا هنروح علي المجلد بتاع المشروع ونكتب الكود دا
   cd user-registration-system

   2 بعد كدت نعمل run عن طريق الكود دا
   python user_registration_system.py
