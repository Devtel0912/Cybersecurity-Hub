document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("computer");
  const nav = document.getElementById("nav-links");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      nav.classList.toggle("active");
    });
  }
});