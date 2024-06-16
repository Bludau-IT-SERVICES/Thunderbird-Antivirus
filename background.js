let apikey_hybridanalysis;

async function loadSettings() {
  await messenger.storage.local.get('apikey').then((result) => {
      console.log("Ihr Hybris-Analysis API-KEY: " + result.apikey);
      apikey_hybridanalysis =  result.apikey;
    });    
}
loadSettings();
browser.messageDisplay.onMessageDisplayed.addListener(tab_mail_open_display);


// Erstelle einen Listener für das "onNewMailReceived"-Ereignis
async function mail_checker2(folder, messageList) {

  messageList.load();
  messageList.loadAttachments();

  // Gib die Liste der Nachrichten aus
  console.log(messageList.messages);

  // Iteriere über die Nachrichten
  for (const message of messageList.messages) {
    // Gib die Absender- und Betreffzeile der Nachricht aus
    console.log(`Absender: ${message[0].sender}`);
    console.log(`Betreff: ${message[0].subject}`);
    // Iteriere über die Nachrichten
    // Lade die Nachricht
    //    message.load();

    // Lade die Anhänge
    //  message.loadAttachments();

    // Prüfe, ob Anhänge vorhanden sind
    if (message.attachments.length > 0) {
      // Ausgabe der Anhänge
      for (const attachment of message.attachments) {
        console.log(attachment.name);
      }

    }

  }
}


async function mail_checker(folder, messageList) {
  //console.log(folder)
  //messageList = messenger.messages.getList(folder);
  let aryMessage = messageList.messages;

  console.log(aryMessage[0]);
  //messageList.load();
  //messageList.loadAttachments();

  console.log(aryMessage[0].subject);
  try {

    let message = aryMessage[0];
    let headerMessageId = message.id;

    let attachments = await browser.messages.listAttachments(headerMessageId);
    console.log(attachments);
    for (let att of attachments) {
      let file = await browser.messages.getAttachmentFile(messageId, att.partName);
      console.log(file);
      let content = await file.text();
    }
  } catch (error) {
    console.log(`Fehler beim Abrufen der Attachments: ${error}`);
  }

  // Check if there are any attachments
  if (attachments.length > 0) {
    // Process the attachments
    for (const attachment of attachments) {
      // Handle the attachment object here
      console.log(attachment.name);
      console.log(attachment.type);
      console.log(attachment.size);
      if (attachment.size <= 100 * 1024 * 1024) {
        // Sende den Anhang an VirusTotal
        let response = await fetch("https://www.virustotal.com/api/v3/files", {
          method: "POST",
          headers: {
            "x-apikey": ""
          },
          body: attachment.file
        });

        if (response.ok) {
          let data = await response.json();
          let fileId = data.data.id;

          // Hole den Analysebericht von VirusTotal
          let reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${fileId}`, {
            headers: {
              "x-apikey": ""
            }
          });
          let reportData = await reportResponse.json();

          // Interpretiere und Ausgabe der Antwortdaten
          if (reportData && reportData.data && reportData.data.attributes) {
            let stats = reportData.data.attributes.stats;
            let malicious = stats.malicious || 0;
            let undetected = stats.undetected || 0;
            console.log(`#######################################`);
            console.log(`# VIRUS TOTAL <-> <->`);
            console.log(`#######################################`);
            console.log(`Datei-ID: ${fileId}`);
            console.log(`Anzahl der Erkennungen: ${malicious}`);
            console.log(`Anzahl der nicht erkannten: ${undetected}`);
          } else {
            console.log("Keine gültigen Daten in der Antwort von VirusTotal gefunden.");
          }
        } else {
          console.error("Fehler beim Senden des Dateianhangs an VirusTotal");
        }
      } else {
        console.log("Dateianhang ist zu groß (> 100 MB).");
      }
    }
  }

  /*
    for (let attachment of messageList.filter(attachment => attachment.type === "application/octet-stream")) {
      
    } */
}

messenger.messages.onNewMailReceived.addListener(mail_checker);


async function send_to_virustotal() {
  // Iterate over the attachments
  for (let att of attachments) {
    // Call the getAttachmentFile() method to get the file for the attachment
    let file = await browser.messages.getAttachmentFile(message.id, att.partName);

    // Call the text() method to get the attachment content as text
    let content = await file.text();

    // Log the attachment content
    console.log(content);
    // Check if there are any attachments
    if (attachments.length > 0) {
      // Process the attachments
      for (const attachment of attachments) {
        const proxyURL = "https://cors-anywhere.herokuapp.com/";
        const virusTotalURL = "https://www.virustotal.com/api/v3/files";

        // Handle the attachment object here
        console.log(attachment.name);
        console.log(attachment.type);
        console.log(attachment.size);
        if (attachment.size <= 100 * 1024 * 1024) {
          // Sende den Anhang an VirusTotal
          let response = await fetch(`${virusTotalURL}`, {
            method: "POST",
            headers: {
              "x-apikey": "",
            },
            body: attachment.file,
            origin: "https://tsecurity.de",
          });

          console.log(response);
          if (response.ok) {
            let data = await response.json();
            let fileId = data.data.id;

            // Hole den Analysebericht von VirusTotal
            let reportResponse = await fetch(`${virusTotalURL}${fileId}`, {
              headers: {
                "x-apikey": ""
              },
              origin: "https://tsecurity.de",
            });
            let reportData = await reportResponse.json();
            console.log(reportData);
            // Interpretiere und Ausgabe der Antwortdaten
            if (reportData && reportData.data && reportData.data.attributes) {
              let stats = reportData.data.attributes.stats;
              let malicious = stats.malicious || 0;
              let undetected = stats.undetected || 0;
              console.log(`#######################################`);
              console.log(`# VIRUS TOTAL <-> <->`);
              console.log(`#######################################`);
              console.log(`Datei-ID: ${fileId}`);
              console.log(`Anzahl der Erkennungen: ${malicious}`);
              console.log(`Anzahl der nicht erkannten: ${undetected}`);
            } else {
              console.log("Keine gültigen Daten in der Antwort von VirusTotal gefunden.");
            }
          } else {
            console.error("Fehler beim Senden des Dateianhangs an VirusTotal");
          }
        } else {
          console.log("Dateianhang ist zu groß (> 100 MB).");
        }
      }
    }

  }
}

/*
async function set_SQLite_db(tab, message) {

  try {
    const SQL = await initSqlJs({ locateFile: filename => `./sql-wasm.wasm` });
    const db = new SQL.Database();

    db.exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)');

    db.exec('INSERT INTO users (name) VALUES (?)', ['John Doe']);

    const users = db.exec('SELECT * FROM users');
    console.log(users);

    // Exportieren Sie die Datenbank in einen Uint8Array
    const data = db.export();

    // Konvertieren Sie den Uint8Array in einen String
    let binary = '';
    const bytes = new Uint8Array(data);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }

    // Speichern Sie den String in der Storage-API
    //browser.storage.local.set({ myDatabase: binary });
    // Speichern Sie Daten
    //await messenger.storage.local.set({db_data: binary});
    // Speichern Sie den String in einer Datei
    const { OS } = ChromeUtils.import("resource://gre/modules/osfile.jsm");
    let path = OS.Path.join(OS.Constants.Path.profileDir, "thundy_av.db");
    let encoder = new TextEncoder();
    let array = encoder.encode(binary);
    let promise = OS.File.writeAtomic(path, array, { tmpPath: path + ".tmp" });

  } catch (error) {
    console.error('SQLite Database Error INIT:', error);
  }

}
*/

function indexedDB_save_hybrid_data_to_db(message, hybrid_data) {
  // Öffnen Sie eine Datenbankverbindung
  let openRequest = indexedDB.open("thunderbird_av", 3);

  openRequest.onupgradeneeded = function (e) {
    let db = e.target.result;

    // Erstellen Sie einen Object Store
    if (!db.objectStoreNames.contains('hybridanalysis')) {

      db.createObjectStore('hybridanalysis', { keyPath: 'messageHeader' });
      console.log('Datenbank hybridanalysis wurde erstellt.')
    }
  };

  // Start the transaction and add data.
  openRequest.onsuccess = function (e) {
    console.log("Datenbank wurde erfolgreich geöffnet/aktualisiert");
    const db = e.target.result;

    // Create a transaction to read and write data.
    const transaction = db.transaction(['hybridanalysis'], 'readwrite');
    const store = transaction.objectStore('hybridanalysis');
    let item = {
      messageHeader: message.headerMessageId, // The email information
      hybrid_submission_id: hybrid_data.submission_id,
      hybrid_job_id: hybrid_data.job_id,
      hybrid_sha256: hybrid_data.sha256,
      author: message.author, // The email ID
      subject: message.subject, // The email information
      created: new Date()
    };

    // Check if the hash is defined and has a valid value.
    if (typeof item.messageHeader !== 'undefined' && item.messageHeader !== '') {
      // Check if the hash already exists.
      let getRequest = store.get(item.messageHeader);
      getRequest.onsuccess = function () {
        if (typeof getRequest.result === 'undefined') {
          // The hash does not exist, add the item.
          let addRequest = store.add(item);
          addRequest.onsuccess = function () {
            console.log('Data successfully added');
          };
          addRequest.onerror = function () {
            console.log('Error adding data');
          };
        } else {
          console.log('The hash already exists');
        }
      };
      getRequest.onerror = function () {
        console.log('Error retrieving data');
      };
    } else {
      console.log('Invalid hash');
    }
  }
  openRequest.onerror = function (e) {
    console.log('Fehler beim Öffnen der Datenbank');
  };  
}



async function chk_cors_ok() {
  // Set the URL to fetch
  const url = "https://www.google.com";

  // Fetch the URL
  const response = await fetch(url);

  // Check the response
  if (response.status === 200) {
    // The request was successful
    const data = await response.text();
    console.log(data);
  } else {
    // The request failed
    console.error(response.statusText);
  }
}

async function sent_to_hybrid_by_attachment(message, attachments) {
  // Get the API key from a configuration file
  const apiKey = apikey_hybridanalysis;

  for (const attachment of attachments) {
    console.log(attachment.name);
    console.log(attachment.type);
    console.log(attachment.size);

    let file = await browser.messages.getAttachmentFile(message.id, attachment.partName);

    // switch-case Anweisung
    switch (attachment.contentType) {
      case 'text/plain':
        console.log('Dies ist eine Textdatei');
        break;
      case 'text/html':
        console.log('Dies ist ein HTML-Dokument');
        break;
      case 'text/css':
        console.log('Dies sind Cascading Style Sheets');
        break;
      case 'text/csv':
        console.log('Dies sind kommagetrennte Werte');
        break;
      case 'text/javascript':
        console.log('Dies ist eine JavaScript-Datei');
        break;
      case 'application/json':
        console.log('Dies sind JSON-Daten');
        break;
      case 'application/xml':
        console.log('Dies sind XML-Daten');
        break;
      case 'application/xhtml+xml':
        console.log('Dies ist ein XHTML-Dokument');
        break;
      default:
        console.log('Gültiger Typ für hybrid-analysis.com | Content-Type' + attachment.contentType);

        const content_of_atachment = file.slice();

        const file_to_submit = new File([content_of_atachment], attachment.name, { type: attachment.contentType });

        const formData = new FormData();
        //formData.append('environment_id', '140');
        formData.append('scan_type', 'all');
        formData.append('file', file_to_submit);

        // Set the request options
        const options = {
          method: 'POST', 
          url: 'https://hybrid-analysis.com/api/v2/quick-scan/file',
          headers: {
            accept: 'application/json',
            'api-key': apikey_hybridanalysis,
            'user-agent': 'Falcon',
            'scan_type': 'all'
          },
          body: formData
        };

        // Send the request and handle the response
        try {
          const response = await fetch(options.url, options);
          const json_data = await response.json();

          if (response.status === 200) {
            console.log('File successfully submitted to Hybrid Analysis.');
            console.log(json_data);
            console.log("**Datendetails:**");
            console.log("  SHA-256:", json_data.sha256);

            console.log("**Scannerergebnisse:**");
            for (const scanner of json_data.scanners) {
              console.log("  Scanner:", scanner.name);
              console.log("    Status:", scanner.status);
            }

            console.log("**Zusätzliche Informationen:**");
            console.log("  Analysis Start Time:", json_data.analysis_start_time);
            console.log("  Whitelist Status:", json_data.whitelist);
            console.log("  Reports:", json_data.reports);
            indexedDB_save_hybrid_data_to_db(message, json_data);
          } else {
            console.error('Failed to submit file to Hybrid Analysis.');
            console.error(json_data);
            console.error(errorData.validation_errors[0].errors[0].message);
          }
        } catch (error) {
          console.error('Error sending file to Hybrid Analysis:', error);
        }
    }
  }
}

//
// background.js Hybrid-Analysis.com Get Report of AV-Scanners
// 
async function get_hybrid_report_by_sha256(hybrid_sha) {

  // Set the request options
  const options = {
    method: 'GET',
    url: 'https://hybrid-analysis.com/api/v2/overview/' + hybrid_sha,
    headers: {
      accept: 'application/json',
      'api-key': apikey_hybridanalysis,
      'user-agent': 'Falcon',
    },

  };

  // Send the request and handle the response
  try {
    const response = await fetch(options.url, options);
    const json_data = await response.json();

    if (response.status === 200) {
      // Dateidetails
      console.log(json_data);
      console.log("Dateidetails:");
      console.log("  SHA-256-Hashwert:", json_data.sha256);
      console.log("  Letzter Dateiname:", json_data.last_file_name);
      console.log("  Weitere Dateinamen:", json_data.other_file_name);
      console.log("  Bedrohungsscore:", json_data.threat_score);
      console.log("  Urteil:", json_data.verdict);
      console.log("  URL-Analyse:", json_data.url_analysis);
      console.log("  Größe:", json_data.size);
      console.log("  Typ:", json_data.type);
      console.log("  Architektur:", json_data.architecture);
      console.log("  Vx-Familie:", json_data.vx_family);
      console.log("  Multiscan-Ergebnis:", json_data.multiscan_result);

      // Scannerergebnisse
      console.log("Scannerergebnisse:");
      for (const scanner of json_data.scanners) {
        console.log("  Scanner:", scanner.name);
        console.log("    Status:", scanner.status);
        if (scanner.anti_virus_results) {
          console.log("      AV-Ergebnisse:");
          for (const avResult of scanner.anti_virus_results) {
            console.log("        AV:", avResult.product);
            console.log("        Urteil:", avResult.verdict);
          }
        }
      }

      // Zusätzliche Informationen
      console.log("Zusätzliche Informationen:");
      console.log("  Analysebeginn:", json_data.analysis_start_time);
      console.log("  Letzte Multiscan:", json_data.last_multiscan);
      console.log("  Tags:", json_data.tags);
      console.log("  Whitelist-Status:", json_data.whitelisted);
      console.log("  Verwandte Elternhashes:", json_data.related_parent_hashes);
      console.log("  Verwandte Kindhashes:", json_data.related_children_hashes);
      console.log("  Berichte:", json_data.reports);

      // Gesamtbewertung
      console.log("Gesamtbewertung:");
      console.log("  Bedrohungsscore:", json_data.threat_score);
      console.log("  Urteil:", json_data.verdict);



      // Additional information
      console.log("Additional Information:");
      console.log("  Analysis start time:", json_data.analysis_start_time);
      console.log("  Last multiscan:", json_data.last_multiscan);
      console.log("  Tags:", json_data.tags);
      console.log("  Whitelist status:", json_data.whitelisted);
      console.log("  Related parent hashes:", json_data.related_parent_hashes);
      console.log("  Related children hashes:", json_data.related_children_hashes);
      console.log("  Reports:", json_data.reports);

      // Overall assessment
      console.log("Overall Assessment:");
      console.log("  Threat score:", json_data.threat_score);
      console.log("  Verdict:", json_data.verdict);


    } else {
      console.log('Failed to Get Report for SHA256 at Hybrid Analysis.');
      console.log(json_data);
      console.log(errorData.validation_errors[0].errors[0].message);
    }
  } catch (error) {
    console.log('Error sending file to Hybrid Analysis:', error);
  }
}
// background.js in Thunderbird extension for Event when opening a Message 
async function tab_mail_open_display(tab, message) {

  // Testing of an Existing Report
  //await get_hybrid_report_by_sha256('ad7cd28d7f559dd16fe83ce62d26340dcd6aaa353e9d137638c7e95ae4053ca3');

  // Log message: "Message displayed in tab {message.id}: {message.subject}"
  console.log(`Folgende Email Nachricht ist aktiv: ${message.author}: ${message.subject}`);

  // Try to load the full message
  try {
    // Get the Full Message with Attachment und save it to message_full
    message_full = await browser.messages.getFull(message.id);

    // Call the listAttachments() method to get the list of attachments
    let attachments = await browser.messages.listAttachments(message.id);

    // Log the attachments
    console.log(attachments);
    if (attachments.length > 0) {
      await sent_to_hybrid_by_attachment(message, attachments);
    }

  } catch (error) {
    // Log the error message
    console.log(`Error with loading the Attachments: ${error}`);
  }
}
