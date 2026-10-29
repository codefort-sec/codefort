import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "#070807",
        surface: "#0D0F0D",
        "surface-raised": "#141714",
        lime: "#D7FF35",
        "lime-muted": "#A8C92A",
        text: "#F2F2ED",
        "text-muted": "#A2A59A",
        "text-dim": "#686D64",
        border: "#343832",
        "border-strong": "#62685B",
        danger: "#FF6B5E",
      },
      fontFamily: {
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
      borderRadius: {
        none: "0px",
        DEFAULT: "2px",
      },
    },
  },
  plugins: [],
};

export default config;
