var app = document.querySelector('#app');
app.innerHTML = '<img src="x" onerror="alert(1)">';
var imported = document.createElement('script');
imported.src = '/path/to/imported/script';
document.head.appendChild(imported);