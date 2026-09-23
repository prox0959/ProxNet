// TR: WebSockets üzerinden sunucuyla iletişim kurmak için.
const socket = io();

let networkData = {
    nodes: [],
    links: []
};

// D3.js SVG setup
const container = document.getElementById('graph-container');
const width = container.clientWidth;
const height = container.clientHeight;

const svg = d3.select("#graph-container").append("svg")
    .attr("width", width)
    .attr("height", height);

// Tooltip setup
const tooltip = d3.select("#tooltip");

// TR: Fizik motoru (güç yönlendirmeli grafik) - Düğümleri iter/çeker
const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(150))
    .force("charge", d3.forceManyBody().strength(-400))
    .force("center", d3.forceCenter(width / 2, height / 2));

let link = svg.append("g").attr("class", "links").selectAll(".link");
let node = svg.append("g").attr("class", "nodes").selectAll(".node");
let labels = svg.append("g").attr("class", "labels").selectAll(".node-label");

function updateGraph(data) {
    // Transform devices to nodes and links
    // TR: Gelen cihaz listesini D3'ün anlayacağı node/link yapısına çeviriyoruz.
    const nodes = [{ id: "Router", group: "router", ip: "Gateway", mac: "", vendor: "", os: "Router" }];
    const links = [];

    let warningCount = 0;

    data.forEach((dev, index) => {
        // Determine color/group based on threats (simulated logic for frontend)
        let group = "safe";
        if (dev.open_ports.includes(445) || dev.open_ports.includes(3389)) {
            group = "warning";
            warningCount++;
        }
        
        nodes.push({
            id: dev.ip,
            ip: dev.ip,
            mac: dev.mac,
            vendor: dev.vendor,
            os: dev.os,
            ports: dev.open_ports.join(', '),
            group: group
        });
        
        links.push({
            source: "Router",
            target: dev.ip
        });
    });

    // Update UI Stats
    document.getElementById('device-count').innerText = data.length;
    
    // Update D3 Data bindings
    link = link.data(links, d => d.source.id + "-" + d.target.id);
    link.exit().remove();
    const linkEnter = link.enter().append("line").attr("class", "link");
    link = linkEnter.merge(link);

    node = node.data(nodes, d => d.id);
    node.exit().remove();
    const nodeEnter = node.enter().append("circle")
        .attr("class", "node")
        .attr("r", d => d.group === "router" ? 20 : 12)
        .attr("fill", d => {
            if (d.group === "router") return "#58a6ff";
            if (d.group === "warning") return "#FFD700";
            if (d.group === "critical") return "#FF4500";
            return "#00FF41"; // Safe
        })
        .on("mouseover", function(event, d) {
            tooltip.transition().duration(200).style("opacity", .9);
            tooltip.html(`
                <strong>IP:</strong> ${d.ip}<br/>
                <strong>MAC:</strong> ${d.mac || 'N/A'}<br/>
                <strong>Vendor:</strong> ${d.vendor || 'N/A'}<br/>
                <strong>OS:</strong> ${d.os || 'N/A'}<br/>
                <strong>Ports:</strong> ${d.ports || 'None'}
            `)
            .style("left", (event.pageX + 10) + "px")
            .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            tooltip.transition().duration(500).style("opacity", 0);
        })
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));
            
    node = nodeEnter.merge(node);

    labels = labels.data(nodes, d => d.id);
    labels.exit().remove();
    const labelsEnter = labels.enter().append("text")
        .attr("class", "node-label")
        .attr("dx", 15)
        .attr("dy", 4)
        .text(d => d.id);
    labels = labelsEnter.merge(labels);

    simulation.nodes(nodes).on("tick", ticked);
    simulation.force("link").links(links);
    simulation.alpha(1).restart();
}

function ticked() {
    link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

    node
        .attr("cx", d => d.x)
        .attr("cy", d => d.y);
        
    labels
        .attr("x", d => d.x)
        .attr("y", d => d.y);
}

// Drag functions
function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}
function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}
function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// Button actions
function triggerScan() {
    document.getElementById('last-scan').innerText = "Scanning...";
    fetch('/api/scan', { method: 'POST' });
}

function updateThreats(threats) {
    const feed = document.getElementById('threat-feed');
    feed.innerHTML = '';
    document.getElementById('threat-count').innerText = threats.length;
    
    // Reverse array to show newest first
    const reversed = [...threats].reverse();
    reversed.forEach(t => {
        const div = document.createElement('div');
        div.className = `threat-item threat-${t.severity}`;
        div.innerHTML = `[${t.timestamp}] <strong>${t.ip}</strong>: ${t.message}`;
        feed.appendChild(div);
    });
}

// Socket events
// TR: Sunucudan yeni ağ verisi geldiğinde grafik ve tehdit listesi güncellenir.
socket.on('update_network', function(data) {
    if(data.devices) updateGraph(data.devices);
    if(data.last_scan) document.getElementById('last-scan').innerText = data.last_scan;
    if(data.threats) updateThreats(data.threats);
});

// Initial load
fetch('/api/devices')
    .then(r => r.json())
    .then(data => {
        if(data.devices) updateGraph(data.devices);
        if(data.last_scan) document.getElementById('last-scan').innerText = data.last_scan;
    });

fetch('/api/threats')
    .then(r => r.json())
    .then(data => {
        if(data.threats) updateThreats(data.threats);
    });
