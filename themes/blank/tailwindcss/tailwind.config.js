/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ["../layouts/**/*.html"],
    theme: {
        colors: {
            "light-primary": "#e6e6e6",
            "light-secondary": "#f5f5f5",
            "light-text": "#303030",

            "dark-primary": "#2f353a",
            "dark-secondary": "#282d34",
            "dark-text": "#bec5d1",

            theme: "#6d79bf",
            transparent: "transparent",
            current: "currentColor"
        }
    },
    plugins: []
};
