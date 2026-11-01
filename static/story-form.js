document.getElementById("story-form")?.addEventListener("submit", function (e) {
  var agree = document.getElementById("agree_terms");
  var btn = document.getElementById("run-story");
  if (agree && !agree.checked) {
    e.preventDefault();
    alert("利用規約への同意が必要です。");
    agree.focus();
    return;
  }
  if (btn) btn.textContent = "紡いでいます…";
});
