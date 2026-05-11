document.addEventListener("DOMContentLoaded", () => {
  const brand = document.querySelector(".brand-mark");
  if (brand) {
    brand.animate(
      [
        { transform: "translateY(0px)" },
        { transform: "translateY(-4px)" },
        { transform: "translateY(0px)" }
      ],
      { duration: 2200, iterations: Infinity }
    );
  }
});
