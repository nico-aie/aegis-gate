// D-M1 component stub. Real implementation lands in milestones D-M2..D-M5.
export default {
  create(_props) {
    const el = document.createElement("div");
    el.dataset.component = "sparkline";
    return el;
  },
};
