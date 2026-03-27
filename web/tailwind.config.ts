import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          blue:    "#38bdf8",   // electric blue — shield outline, primary accent
          success: "#4ade80",   // green — false positive / safe
          danger:  "#f87171",   // red — true positive / vulnerability
        },
      },
    },
  },
  plugins: [],
};

export default config;
