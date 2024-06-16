// Event-Listener für das Laden der Seite
document.addEventListener('DOMContentLoaded', function() {
    // Abrufen der gespeicherten Einstellung
    browser.storage.local.get('apikey').then((result) => {
      document.getElementById('apikey').value = result.apikey;
    });
  });
  
  document.getElementById('save').addEventListener('click', function() {
    let mySetting = document.getElementById('apikey').value;
    browser.storage.local.set({
        apikey: mySetting
    });
  });