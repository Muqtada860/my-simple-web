"""
لاب: XSS المنعكس (Reflected XSS)
الموقع: منتدى IKU التقني (موقع واقعي لأغراض التدريب)
الثغرة: قيمة q تُعاد كما هي داخل HTML بدون أي تهريب (escaping).
الهدف: تمرير وسم <script> يُظهر أنه نُفّذ فعلياً داخل الصفحة.
"""
import os
import re
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAG = "IKU{r3fl3ct3d_xss_n0_3sc4p1ng}"

PAGE = """
<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>منتدى IKU التقني</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
<style>
body{font-family:'Cairo',sans-serif;background:#f4f6fb}
.navbar{background:#0b3d91}
.navbar-brand{font-weight:700}
.hero{background:linear-gradient(135deg,#0b3d91,#1565c0);color:#fff;padding:3rem 0}
.sidebar .list-group-item{cursor:pointer}
.thread-card{border:none;box-shadow:0 2px 8px rgba(0,0,0,.06)}
footer{background:#0b3d91;color:#cfe0ff}
</style>
</head><body>

<nav class="navbar navbar-dark navbar-expand-lg">
  <div class="container">
    <a class="navbar-brand" href="/">💻 منتدى IKU التقني</a>
    <div class="d-flex gap-3">
      <a class="nav-link text-light" href="#">الرئيسية</a>
      <a class="nav-link text-light" href="#">الأقسام</a>
      <a class="nav-link text-light" href="#">الأعضاء</a>
      <a class="nav-link text-light" href="#">تسجيل الدخول</a>
    </div>
  </div>
</nav>

<div class="hero text-center">
  <div class="container">
    <h2>منتدى النقاش التقني لطلاب كلية الإمام الكاظم</h2>
    <p class="mb-0">شارك، ناقش، وابحث في آلاف المواضيع التقنية</p>
  </div>
</div>

<div class="container py-5">
  <div class="row">
    <div class="col-lg-3 sidebar mb-4">
      <div class="list-group">
        <div class="list-group-item">🖥️ أنظمة التشغيل</div>
        <div class="list-group-item">🔐 الأمن السيبراني</div>
        <div class="list-group-item">🌐 الشبكات</div>
        <div class="list-group-item">📱 تطوير التطبيقات</div>
      </div>
    </div>

    <div class="col-lg-9">
      <div class="card thread-card p-4 mb-4">
        <h5 class="mb-3">🔍 ابحث عن موضوع</h5>
        <p class="text-muted small">محرك البحث هذا يعيد عرض كلمة البحث داخل الصفحة مباشرة — جزء شائع من واجهات المنتديات، وفرصة جيدة لاختبار سلوك الموقع تجاه المدخلات غير المتوقعة.</p>
        <form class="d-flex" method="get">
          <input class="form-control me-2" type="text" name="q" value="{{ q_raw }}" placeholder="ابحث عن موضوع، كاتب، أو كلمة مفتاحية...">
          <button class="btn btn-primary">بحث</button>
        </form>
      </div>

      <div class="card thread-card p-4">
        <h6 class="text-muted">نتائج البحث عن:</h6>
        <div class="border rounded p-3 bg-light">{{ q_html|safe }}</div>
      </div>

      {% if flag %}
      <div class="alert alert-success mt-4">
        🎉 أثبتت أن السكربت ينفذ فعلياً داخل الصفحة (Reflected XSS)! الفلاك:
        <code>{{ flag }}</code>
      </div>
      {% endif %}

      <div class="mt-5">
        <h6 class="text-muted mb-3">مواضيع شائعة</h6>
        <div class="card thread-card p-3 mb-2 d-flex flex-row justify-content-between">
          <span>كيف أبدأ بتعلم اختبار الاختراق؟</span><span class="text-muted small">48 رد</span>
        </div>
        <div class="card thread-card p-3 d-flex flex-row justify-content-between">
          <span>أفضل أدوات مراقبة الشبكة لعام 2026</span><span class="text-muted small">21 رد</span>
        </div>
      </div>
    </div>
  </div>
</div>

<footer class="text-center py-4 mt-5">
  <small>منتدى IKU التقني — كلية الإمام الكاظم (ع) — قسم الأمن السيبراني</small>
</footer>
</body></html>
"""

SCRIPT_PATTERN = re.compile(r"<script[^>]*>.*?</script>|on\w+\s*=", re.IGNORECASE | re.DOTALL)


@app.route("/")
def index():
    q = request.args.get("q", "")
    flag = FLAG if q and SCRIPT_PATTERN.search(q) else None
    return render_template_string(PAGE, q_raw=q, q_html=q, flag=flag)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8013)))
