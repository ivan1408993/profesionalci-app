const employerToggle = document.getElementById('employerMenu');
const neonMenu = document.getElementById('employerNeonMenu');

employerToggle.addEventListener('click', (e) => {
    e.preventDefault();
    neonMenu.classList.toggle('open');
});

// Klik van menija zatvara
document.addEventListener('click', (e) => {
    if (!neonMenu.contains(e.target) && e.target !== employerToggle) {
        neonMenu.classList.remove('open');
    }
});

// Hover / selektovanje li elementa
const liItems = neonMenu.querySelectorAll('li');
liItems.forEach(li => {
    li.addEventListener('click', () => {
        liItems.forEach(i => i.classList.remove('selected'));
        li.classList.add('selected');
    });
});

// Hue slider (ako želiš da ostaviš kontrolu boja)
const $hue1 = document.querySelector('#h1');
const $hue2 = document.querySelector('#h2');

$hue1?.addEventListener('input', (event) => {
    document.body.style.setProperty('--hue1', event.target.value);
});
$hue2?.addEventListener('input', (event) => {
    document.body.style.setProperty('--hue2', event.target.value);
});
