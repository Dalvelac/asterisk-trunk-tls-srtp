"use strict";
const player = document.querySelector("#tone");
const buttons = Array.from(document.querySelectorAll("[data-tone]"));
let selected = null;
function idle() {
  for (const button of buttons) button.setAttribute("aria-pressed", "false");
  selected = null;
}
player.addEventListener("ended", idle);
player.addEventListener("error", idle);
for (const button of buttons) {
  button.addEventListener("click", async () => {
    const stop = selected === button;
    player.pause();
    idle();
    if (stop) return;
    selected = button;
    button.setAttribute("aria-pressed", "true");
    player.src = "assets/tone-" + button.dataset.tone + ".wav";
    try {
      await player.play();
    } catch {
      if (selected === button) idle();
    }
  });
}
