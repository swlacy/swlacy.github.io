/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ["themes/blank/layouts/**/*.html"],
    theme: {
        colors: {
            "light-background": "#f9f9f8",
            "light-accent": "#ebebe9",
            "light-text": "#21201c",

            "dark-background": "#1b1b1a",
            "dark-accent": "#30302e",
            "dark-text": "#b2b1aa",

            theme: "#2d87b4",
            transparent: "transparent",
            current: "currentColor"
        }
    },
    plugins: []
};
