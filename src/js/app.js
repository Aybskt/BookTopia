const swiperElement = document.querySelector(".home");

if (swiperElement && typeof Swiper !== "undefined") {
  new Swiper(".home", {
    centeredSlides: true,
    loop: true,
    speed: 700,
    autoplay: {
      delay: 4500,
      disableOnInteraction: false,
      pauseOnMouseEnter: true,
    },
    pagination: {
      el: ".swiper-pagination",
      clickable: true,
    },
  });
}

const header = document.querySelector("header");
const scrollButton = document.querySelector(".scroll");

function updateScrolledState() {
  const isScrolled = window.scrollY > 24;
  header?.classList.toggle("is-scrolled", isScrolled);

  if (scrollButton) {
    scrollButton.style.display = window.scrollY > 240 ? "grid" : "none";
  }
}

window.addEventListener("scroll", updateScrolledState, { passive: true });
updateScrolledState();

scrollButton?.addEventListener("click", () => {
  window.scrollTo({ top: 0, behavior: "smooth" });
});

if (scrollButton) {
  scrollButton.setAttribute("role", "button");
  scrollButton.setAttribute("tabindex", "0");
  scrollButton.setAttribute("aria-label", "Revenir en haut de la page");
  scrollButton.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  });
}

const footer = document.querySelector(".footer-container");
if (scrollButton && footer && "IntersectionObserver" in window) {
  const footerObserver = new IntersectionObserver(
    ([entry]) => scrollButton.classList.toggle("is-near-footer", entry.isIntersecting),
    { threshold: 0.08 }
  );
  footerObserver.observe(footer);
}

const preloader = document.querySelector(".preloader");

const dismissPreloader = () => {
  if (!preloader) return;

  window.requestAnimationFrame(() => preloader.classList.add("hide"));
  window.setTimeout(() => preloader.remove(), 500);
};

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", dismissPreloader, { once: true });
} else {
  dismissPreloader();
}

const navToggle = document.querySelector(".nav-toggle");
const navigation = document.querySelector("#primary-navigation");

function closeNavigation() {
  navToggle?.setAttribute("aria-expanded", "false");
  navToggle?.setAttribute("aria-label", "Ouvrir le menu");
  navigation?.classList.remove("is-open");
  document.body.classList.remove("menu-open");
}

navToggle?.addEventListener("click", () => {
  const willOpen = navToggle.getAttribute("aria-expanded") !== "true";
  navToggle.setAttribute("aria-expanded", String(willOpen));
  navToggle.setAttribute("aria-label", willOpen ? "Fermer le menu" : "Ouvrir le menu");
  navigation?.classList.toggle("is-open", willOpen);
  document.body.classList.toggle("menu-open", willOpen);
});

navigation?.querySelectorAll("a").forEach((link) => {
  const currentPage = window.location.pathname.split("/").pop() || "index.php";
  const linkPage = new URL(link.href).pathname.split("/").pop();

  if (currentPage === linkPage) {
    link.setAttribute("aria-current", "page");
  }

  link.addEventListener("click", closeNavigation);
});

document.addEventListener("click", (event) => {
  if (!navigation?.classList.contains("is-open")) return;
  if (navigation.contains(event.target) || navToggle?.contains(event.target)) return;
  closeNavigation();
});

window.addEventListener("resize", () => {
  if (window.innerWidth > 820) closeNavigation();
});

document.querySelectorAll(".btn-animate").forEach((button) => {
  if (button.querySelector(".button-label")) return;
  const label = document.createElement("span");
  label.className = "button-label";
  label.textContent = button.textContent.trim();
  button.replaceChildren(label);
});
