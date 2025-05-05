const API_KEY = "Add_VirusTotal_API_Key_Here";


document.getElementById('logout').addEventListener('click', async (event) => {
    try {
        const response = await fetch('http://127.0.0.1:5000/logout', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        if (response.ok) {
            console.log(response)
            window.location.href = '/login.html';
        } else {
            document.getElementById('response').textContent = 'An error occurred';
        }
    } catch (error) {
        document.getElementById('response').textContent = 'An error* occurred';
    }
});

document.getElementById('alert').addEventListener('click', function() {
    const a = document.getElementById('alert');
    const l = document.getElementById('logs');
    const t = document.getElementById('traffic');
    const s = document.getElementById('tools');

    a.className = 'atab';
    l.className = 'tab';
    t.className = 'tab';
    s.className = 'tab';

    const ac = document.getElementById('calert');
    const lc = document.getElementById('clogs');
    const tc = document.getElementById('ctraffic');
    const sc = document.getElementById('cscan');

    ac.style.display = '';
    lc.style.display = 'none';
    tc.style.display = 'none';
    sc.style.display = 'none';


});

document.getElementById('logs').addEventListener('click', function() {
    const a = document.getElementById('alert');
    const l = document.getElementById('logs');
    const t = document.getElementById('traffic');
    const s = document.getElementById('tools');

    a.className = 'tab';
    l.className = 'atab';
    t.className = 'tab';
    s.className = 'tab';

    const ac = document.getElementById('calert');
    const lc = document.getElementById('clogs');
    const tc = document.getElementById('ctraffic');
    const sc = document.getElementById('cscan');

    ac.style.display = 'none';
    lc.style.display = '';
    tc.style.display = 'none';
    sc.style.display = 'none';


});

document.getElementById('traffic').addEventListener('click', function() {
    const a = document.getElementById('alert');
    const l = document.getElementById('logs');
    const t = document.getElementById('traffic');
    const s = document.getElementById('tools');

    a.className = 'tab';
    l.className = 'tab';
    t.className = 'atab';
    s.className = 'tab';

    const ac = document.getElementById('calert');
    const lc = document.getElementById('clogs');
    const tc = document.getElementById('ctraffic');
    const sc = document.getElementById('cscan');

    ac.style.display = 'none';
    lc.style.display = 'none';
    tc.style.display = '';
    sc.style.display = 'none';



});

document.getElementById('tools').addEventListener('click', function() {
    const a = document.getElementById('alert');
    const l = document.getElementById('logs');
    const t = document.getElementById('traffic');
    const s = document.getElementById('tools');

    a.className = 'tab';
    l.className = 'tab';
    t.className = 'tab';
    s.className = 'atab';

    const ac = document.getElementById('calert');
    const lc = document.getElementById('clogs');
    const tc = document.getElementById('ctraffic');
    const sc = document.getElementById('cscan');

    ac.style.display = 'none';
    lc.style.display = 'none';
    tc.style.display = 'none';
    sc.style.display = '';



});

async function getData() {
    var alerts, logs, traffic
    try {
        const aresponse = await fetch('http://127.0.0.1:5000/alerts', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });

        if (aresponse.ok) {
            alerts = await aresponse.json();
        }
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }

    try {
        const lresponse = await fetch('http://127.0.0.1:5000/logs', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });

        if (lresponse.ok) {
            logs = await lresponse.json();
        }
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }

    try {
        const tresponse = await fetch('http://127.0.0.1:5000/traffic', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });

        if (tresponse.ok) {
            traffic = await tresponse.json();
        }
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }

    fillalerts(alerts);
    filllogs(logs);
    filltraffic(traffic);

}


function fillalerts(alerts) {
    const columns = {
        'time': 'Time',
        'src_ip': 'Source IP',
        'src_port': 'Source Port',
        'dst_port': 'Destination Port',
        'proto': 'Protocol',
        'type': 'Detection Reason'
    };
    const atable = document.getElementById('atable');
    const stable = document.getElementById('stable');
    atable.innerHTML = '';
    stable.innerHTML = '';

    const createRow = () => {
        const row = document.createElement('tr');
        Object.keys(columns).forEach(column => {
            const cell = document.createElement('th');
            cell.textContent = columns[column];
            row.appendChild(cell);
        });
        return row;
    };
    atable.appendChild(createRow());
    stable.appendChild(createRow());

    alerts.forEach(alert => {

        if (alert.label != 0) {
            const row = document.createElement('tr');
            Object.keys(columns).forEach(column => {
                const cell = document.createElement('td');
                cell.textContent = alert[column];
                row.appendChild(cell);
            })

            if (alert.label == -1)
                stable.appendChild(row);
            else if (alert.label == 1)
                atable.appendChild(row);
        }
    });
}


function filltraffic(traffic) {
    const columns = {
        'time': 'Time',
        'src_ip': 'Source IP',
        'src_port': 'Source Port',
        'dst_ip': 'Destination IP',
        'dst_port': 'Destination Port',
        'proto': 'Protocol'
    };
    const ttable = document.getElementById('ttable');
    ttable.innerHTML = '';


    const row = document.createElement('tr');
    Object.keys(columns).forEach(column => {
        const cell = document.createElement('th');
        cell.textContent = columns[column];
        row.appendChild(cell);
    });
    ttable.appendChild(row);

    traffic.forEach(t => {
        const row = document.createElement('tr');
        Object.keys(columns).forEach(column => {
            const cell = document.createElement('td');
            cell.textContent = t[column];
            row.appendChild(cell);
        })

        ttable.appendChild(row);

    });
}



function filllogs(logs) {

    const container = document.getElementById("clogs");

    Object.keys(logs).forEach(key => {
        const keyItem = document.createElement("div");
        keyItem.className = "key-item";

        const ebutton = document.createElement("button");
        ebutton.textContent = "+";
        ebutton.setAttribute("aria-expanded", "false");

        const keyLabel = document.createElement("span");
        keyLabel.textContent = key;

        keyItem.appendChild(ebutton);
        keyItem.appendChild(keyLabel);
        container.appendChild(keyItem);

        const scontainer = document.createElement("div");
        scontainer.className = "value-container";
        scontainer.style.display = "none";

        logs[key].forEach(value => {
            const valueItem = document.createElement("div");
            valueItem.className = "value-item";
            valueItem.textContent = value;
            scontainer.appendChild(valueItem);
            valueItem.addEventListener('click', function() {
                getFile(key + '\\\\' + value);
            });
        });
        container.appendChild(scontainer);

        ebutton.addEventListener("click", () => {
            const isExpanded = ebutton.getAttribute("aria-expanded") === "true";

            if (isExpanded) {
                scontainer.style.display = "none";
                ebutton.textContent = "+";
                ebutton.setAttribute("aria-expanded", "false");
            } else {
                scontainer.style.display = "block";
                ebutton.textContent = "-";
                ebutton.setAttribute("aria-expanded", "true");
            }
        });
    });
}

async function getFile(fileName) {
    fetch('http://127.0.0.1:5000/file?file_name=' + fileName, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        }).then(response => {
            if (response.ok) {
                return response.blob();
            }
        }).then(blob => {
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = fileName;
            link.click();
        })
        .catch(error => {
            console.error('Error fetching file:', error);
        });


}


document.getElementById('fileScan').addEventListener('click', fileScan);
document.getElementById('urlScan').addEventListener('click', urlScan);
document.getElementById('ipScan').addEventListener('click', ipScan);

async function fileScan() {
    const fileInput = document.getElementById("fileInput");
    const status = document.getElementById("fileStatus");
    const r = document.getElementById("fileResult");
    r.innerHTML = '';
    status.innerHTML = '';

    if (!fileInput.files.length) {
        status.innerHTML = "Please select a file first.";
        return;
    }

    const file = fileInput.files[0];
    status.innerText = "Uploading file to VirusTotal...";

    const formData = new FormData();
    formData.append("file", file);

    try {
        var response = await fetch("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY
            },
            body: formData
        });

        let result = await response.json();
        if (!result.data) {
            status.innerHTML = "File upload failed";
        }

        const analysisId = result.data.id;
        status.innerText = "File uploaded. Scanning...";

        await checkScanResult(analysisId, status, r);
    } catch (error) {
        status.innerText = "Error: " + error.message;
    }
}


async function urlScan() {
    const Url = document.getElementById("urlInput").value;
    const status = document.getElementById("urlStatus");
    const r = document.getElementById("urlResult");
    r.innerHTML = '';

    const isValid = (() => {
        try {
            new URL(Url);
            return true;
        } catch (_) {
            return false;
        }
    })();

    if (!isValid) {
        status.innerHTML = "Please enter a valid URL.";
        return;
    }

    status.innerText = "Uploading URL to VirusTotal...";

    try {
        var response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=` + Url

        });

        let result = await response.json();
        if (!result.data) {
            status.innerHTML = "URL upload failed";
        }

        const analysisId = result.data.id;
        status.innerText = "URL uploaded. Scanning...";

        await checkScanResult(analysisId, status, r);
    } catch (error) {
        status.innerText = "Error: " + error.message;
    }
}

async function checkScanResult(analysisId, s, r) {

    while (true) {
        try {
            var response = await fetch('https://www.virustotal.com/api/v3/analyses/' + analysisId, {
                method: "GET",
                headers: {
                    "x-apikey": API_KEY
                }
            });

            let data = await response.json();
            let status = data.data.attributes.status;

            if (status === 'completed') {
                s.innerText = "Scan completed!";
                var stats = data.data.attributes.stats;
                r.innerText =
                    `Result:
                Malicious: ${stats.malicious}\n` +
                    `   Suspicious: ${stats.suspicious}\n` +
                    `   Undetected: ${stats.undetected}`;
                break;
            } else {
                await new Promise(resolve => setTimeout(resolve, 10000));
            }
        } catch (error) {
            s.innerText = "Error in fetching scan result: " + error.message;
        }
    }
}


async function ipScan() {
    const ipInput = document.getElementById("ipInput").value;
    const status = document.getElementById("ipStatus");
    const r = document.getElementById("ipResult");
    r.innerHTML = '';
    status.innerHTML = '';

    const isValidIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ipInput) && ipInput.split('.').every(num => parseInt(num) >= 0 && parseInt(num) <= 255);
    const isValidIPv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(ipInput);
    const isValid = isValidIPv4 || isValidIPv6;

    if (!isValid) {
        status.innerHTML = "Please enter a valid IP.";
        return;
    }

    try {
        var response = await fetch('https://www.virustotal.com/api/v3/ip_addresses/' + ipInput, {
            headers: {
                'x-apikey': API_KEY
            }
        });
        let data = await response.json();
        console.log(data);
        if (data.data) {
            const attributes = data.data.attributes;
            r.innerText = `Country: ${attributes.country}\n` +
                `ISP: ${attributes.as_owner}\n` +
                `Analysis Stats:\n` +
                `  Malicious: ${attributes.last_analysis_stats.malicious}\n` +
                `  Suspicious: ${attributes.last_analysis_stats.suspicious}\n` +
                `  Undetected: ${attributes.last_analysis_stats.undetected}\n`;
            r.appendChild(document.createElement('button')).innerText = 'More Info';
            r.lastChild.addEventListener('click', function() {
                r.removeChild(r.lastChild);
                r.innerText += `\n` +
                    `whois result:\n` +
                    `  ${attributes.whois}\n`;
            })
        } else {
            status.innerHTML = "IP analysis failed";
        }
    } catch (error) {
        console.log('Error analyzing IP:' + error);
    }
}


getData();
setInterval(getData, 180000);