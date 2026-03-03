import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0a0a",
        card: "#111111",
        border: "#222222",
        accent: "#22c55e",
      },
    },
  },
  plugins: [],
};

export default config;
