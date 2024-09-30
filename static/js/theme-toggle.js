// document.getElementById('theme-toggle').addEventListener('click', function() {
//     var body = document.body;
//     if (body.classList.contains('light-mode')) {
//         body.classList.remove('light-mode');
//         body.classList.add('dark-mode');
//         this.textContent = 'Switch to Light Mode';
//     } else {
//         body.classList.remove('dark-mode');
//         body.classList.add('light-mode');
//         this.textContent = 'Switch to Dark Mode';
//     }
// });



document.getElementById('theme-toggle').addEventListener('click', function(e) {
    e.preventDefault();
    var body = document.body;
    var themeToggle = document.getElementById('theme-toggle');

    if (body.classList.contains('light-mode')) {
        body.classList.remove('light-mode');
        body.classList.add('dark-mode');
        themeToggle.textContent = 'Switch to Light Mode';
    } else {
        body.classList.remove('dark-mode');
        body.classList.add('light-mode');
        themeToggle.textContent = 'Switch to Dark Mode';
    }
});
