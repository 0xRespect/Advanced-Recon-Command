# تعليمات رفع المشروع على GitHub

## الخطوات:

### 1. إنشاء مستودع جديد على GitHub

1. اذهب إلى [GitHub.com](https://github.com) وسجل الدخول
2. اضغط على زر **"+"** في أعلى الصفحة واختر **"New repository"**
3. املأ المعلومات:
   - **Repository name**: `ReconForge` (أو أي اسم تريده)
   - **Description**: `A powerful web-based reconnaissance command generator for bug bounty hunters`
   - اختر **Public** أو **Private** حسب رغبتك
   - **لا** تضع علامة على "Initialize with README" (لأن لدينا ملف README بالفعل)
4. اضغط **"Create repository"**

### 2. ربط المشروع المحلي مع GitHub

بعد إنشاء المستودع، ستظهر لك GitHub تعليمات. استخدم الأوامر التالية:

```bash
# أضف المستودع البعيد (استبدل YOUR_USERNAME باسم المستخدم الخاص بك)
git remote add origin https://github.com/YOUR_USERNAME/ReconForge.git

# ارفع الكود
git branch -M main
git push -u origin main
```

### 3. أوامر سريعة (استبدل YOUR_USERNAME)

```bash
git remote add origin https://github.com/YOUR_USERNAME/ReconForge.git
git branch -M main
git push -u origin main
```

### 4. تحديث معلومات Git (اختياري)

إذا أردت تغيير اسم المستخدم والبريد الإلكتروني:

```bash
# للتطبيق على جميع المشاريع (عالمي)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# أو لهذا المشروع فقط (محلي)
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

---

## ملاحظات مهمة:

- ✅ تم إنشاء ملف `.gitignore` لحماية الملفات الحساسة
- ✅ تم إنشاء أول commit بنجاح
- ✅ المشروع جاهز للرفع على GitHub

## إذا واجهت مشكلة في المصادقة:

إذا طُلب منك اسم المستخدم وكلمة المرور:
- استخدم **Personal Access Token** بدلاً من كلمة المرور
- أنشئه من: Settings → Developer settings → Personal access tokens → Tokens (classic)

