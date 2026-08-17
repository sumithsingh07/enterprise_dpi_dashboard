/* ============================================================
   ENTERPRISE DPI DASHBOARD
   dashboard.js
   ============================================================ */

(function () {
    "use strict";

    let protocolChart = null;
    let applicationChart = null;

    let trafficData = [];
    let currentPage = 1;

    const ROWS_PER_PAGE = 20;

    /* ============================================================
       HELPER FUNCTIONS
       ============================================================ */

    function getElement(...ids) {
        for (const id of ids) {
            const element = document.getElementById(id);
            if (element) {
                return element;
            }
        }
        return null;
    }

    function numberValue(value) {
        if (value === null || value === undefined || value === "") {
            return 0;
        }

        const n = Number(value);

        return Number.isFinite(n) ? n : 0;
    }

    function formatNumber(value) {
        return numberValue(value).toLocaleString("en-IN");
    }

    function safeArray(value) {
        return Array.isArray(value) ? value : [];
    }

    /* ============================================================
       API FETCH
       ============================================================ */

    async function fetchDashboardData() {

        try {

            const response = await fetch("/api/dashboard", {
                method: "GET",
                cache: "no-store",
                headers: {
                    "Accept": "application/json"
                }
            });

            if (!response.ok) {
                throw new Error(
                    "Dashboard API returned HTTP " + response.status
                );
            }

            const data = await response.json();

            console.log("DASHBOARD API DATA:", data);

            return data;

        } catch (error) {

            console.error("Dashboard API error:", error);

            return null;
        }
    }


    /* ============================================================
       FIND VALUES FROM DIFFERENT POSSIBLE API FORMATS
       ============================================================ */

    function findValue(object, names) {

        if (!object || typeof object !== "object") {
            return 0;
        }

        for (const name of names) {

            if (
                Object.prototype.hasOwnProperty.call(object, name) &&
                object[name] !== null &&
                object[name] !== undefined
            ) {
                return numberValue(object[name]);
            }
        }

        return 0;
    }


    /* ============================================================
       UPDATE SUMMARY CARDS
       ============================================================ */

    function updateSummary(data) {

        if (!data) {
            return;
        }

        let root = data;

        if (data.data && typeof data.data === "object") {
            root = data.data;
        }

        if (data.dashboard && typeof data.dashboard === "object") {
            root = data.dashboard;
        }

        const total = findValue(root, [
            "total_packets",
            "totalPackets",
            "packets",
            "total"
        ]);

        const tls = findValue(root, [
            "tls_packets",
            "tlsPackets",
            "tls",
            "TLS"
        ]);

        const dns = findValue(root, [
            "dns_packets",
            "dnsPackets",
            "dns",
            "DNS"
        ]);

        const anomalies = findValue(root, [
            "ml_anomalies",
            "mlAnomalies",
            "anomalies",
            "ML_anomalies"
        ]);


        const totalElement = getElement(
            "totalPackets",
            "total-packets",
            "total_packets",
            "totalPacketsValue"
        );

        const tlsElement = getElement(
            "tlsPackets",
            "tls-packets",
            "tls_packets",
            "tlsPacketsValue"
        );

        const dnsElement = getElement(
            "dnsPackets",
            "dns-packets",
            "dns_packets",
            "dnsPacketsValue"
        );

        const anomalyElement = getElement(
            "mlAnomalies",
            "ml-anomalies",
            "ml_anomalies",
            "anomalies",
            "mlAnomaliesValue"
        );


        if (totalElement) {
            totalElement.textContent = formatNumber(total);
        }

        if (tlsElement) {
            tlsElement.textContent = formatNumber(tls);
        }

        if (dnsElement) {
            dnsElement.textContent = formatNumber(dns);
        }

        if (anomalyElement) {
            anomalyElement.textContent = formatNumber(anomalies);
        }
    }


    /* ============================================================
       EXTRACT PROTOCOL DATA
       ============================================================ */

    function extractProtocolData(data) {

        let protocols = [];

        if (!data) {
            return protocols;
        }

        /*
         Possible API formats:

         {
             "protocol_distribution": [...]
         }

         or

         {
             "protocols": [...]
         }

         or

         {
             "protocol_distribution": {
                 "TCP": 10375,
                 "UDP": 7058
             }
         }
        */

        if (Array.isArray(data.protocol_distribution)) {
            protocols = data.protocol_distribution;
        }

        else if (Array.isArray(data.protocols)) {
            protocols = data.protocols;
        }

        else if (
            data.protocol_distribution &&
            typeof data.protocol_distribution === "object"
        ) {

            protocols = Object.entries(
                data.protocol_distribution
            ).map(function ([protocol, total]) {

                return {
                    protocol: protocol,
                    total: total
                };

            });
        }

        else if (
            data.protocols &&
            typeof data.protocols === "object"
        ) {

            protocols = Object.entries(
                data.protocols
            ).map(function ([protocol, total]) {

                return {
                    protocol: protocol,
                    total: total
                };

            });
        }

        return protocols;
    }


    /* ============================================================
       NORMALIZE PROTOCOL NAME
       ============================================================ */

    function normalizeProtocol(protocol) {

        if (protocol === null || protocol === undefined) {
            return "UNKNOWN";
        }

        const p = String(protocol).toUpperCase().trim();

        if (p === "6") {
            return "TCP";
        }

        if (p === "17") {
            return "UDP";
        }

        return p;
    }


    /* ============================================================
       PROTOCOL CHART
       ============================================================ */

    function updateProtocolChart(data) {

        const canvas = getElement(
            "protocolChart",
            "protocolDistributionChart",
            "protocol-chart"
        );

        if (!canvas) {
            console.warn("Protocol chart canvas not found.");
            return;
        }

        const protocolRows = extractProtocolData(data);

        let tcp = 0;
        let udp = 0;

        protocolRows.forEach(function (row) {

            const protocol = normalizeProtocol(
                row.protocol ||
                row.name ||
                row.label
            );

            const total = findValue(row, [
                "total",
                "count",
                "packets",
                "value"
            ]);

            if (protocol === "TCP") {
                tcp += total;
            }

            else if (protocol === "UDP") {
                udp += total;
            }
        });


        /*
         If API does not provide protocol_distribution,
         calculate directly from known dashboard values.
        */

        if (tcp === 0) {
            tcp = findValue(data, [
                "tcp_packets",
                "tcpPackets",
                "tcp"
            ]);
        }

        if (udp === 0) {
            udp = findValue(data, [
                "udp_packets",
                "udpPackets",
                "udp"
            ]);
        }


        if (protocolChart) {
            protocolChart.destroy();
        }


        const ctx = canvas.getContext("2d");


        protocolChart = new Chart(ctx, {

            type: "bar",

            data: {

                labels: ["TCP", "UDP"],

                datasets: [

                    {
                        label: "TCP",
                        data: [tcp, 0],
                        backgroundColor: "#2196f3",
                        borderColor: "#1976d2",
                        borderWidth: 1
                    },

                    {
                        label: "UDP",
                        data: [0, udp],
                        backgroundColor: "#ff5c7a",
                        borderColor: "#e91e63",
                        borderWidth: 1
                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: true
                    },

                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                return (
                                    context.dataset.label +
                                    ": " +
                                    formatNumber(context.raw)
                                );
                            }
                        }
                    }

                },

                scales: {

                    x: {
                        stacked: false
                    },

                    y: {

                        beginAtZero: true,

                        ticks: {

                            callback: function (value) {
                                return formatNumber(value);
                            }

                        }

                    }

                }

            }

        });

    }


    /* ============================================================
       APPLICATION DATA
       ============================================================ */

    function extractApplicationData(data) {

        if (!data) {
            return [];
        }

        if (Array.isArray(data.application_distribution)) {
            return data.application_distribution;
        }

        if (Array.isArray(data.applications)) {
            return data.applications;
        }

        if (
            data.application_distribution &&
            typeof data.application_distribution === "object"
        ) {

            return Object.entries(
                data.application_distribution
            ).map(function ([application, total]) {

                return {
                    application: application,
                    total: total
                };

            });
        }

        if (
            data.applications &&
            typeof data.applications === "object"
        ) {

            return Object.entries(
                data.applications
            ).map(function ([application, total]) {

                return {
                    application: application,
                    total: total
                };

            });
        }

        return [];
    }


    /* ============================================================
       APPLICATION CHART
       ============================================================ */

    function updateApplicationChart(data) {

        const canvas = getElement(
            "applicationChart",
            "applicationDistributionChart",
            "application-chart"
        );

        if (!canvas) {
            console.warn("Application chart canvas not found.");
            return;
        }

        const rows = extractApplicationData(data);

        const labels = [];
        const values = [];


        rows.forEach(function (row) {

            const application =
                row.application ||
                row.app ||
                row.name ||
                row.label ||
                "UNKNOWN";

            const total = findValue(row, [
                "total",
                "count",
                "packets",
                "value"
            ]);

            labels.push(application);
            values.push(total);

        });


        /*
         If no application data exists,
         use protocol/application information from
         the database response if available.
        */

        if (labels.length === 0) {

            const protocolRows = extractProtocolData(data);

            protocolRows.forEach(function (row) {

                const protocol = normalizeProtocol(
                    row.protocol ||
                    row.name ||
                    row.label
                );

                const total = findValue(row, [
                    "total",
                    "count",
                    "packets",
                    "value"
                ]);

                if (protocol !== "UNKNOWN") {
                    labels.push(protocol);
                    values.push(total);
                }

            });

        }


        if (applicationChart) {
            applicationChart.destroy();
        }


        const ctx = canvas.getContext("2d");


        applicationChart = new Chart(ctx, {

            type: "bar",

            data: {

                labels: labels,

                datasets: [

                    {
                        label: "Applications",
                        data: values,
                        backgroundColor: "#64b5e8",
                        borderColor: "#2196f3",
                        borderWidth: 1
                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {
                        display: true
                    },

                    tooltip: {

                        callbacks: {

                            label: function (context) {

                                return (
                                    "Packets: " +
                                    formatNumber(context.raw)
                                );

                            }

                        }

                    }

                },

                scales: {

                    x: {

                        ticks: {
                            autoSkip: false,
                            maxRotation: 45,
                            minRotation: 0
                        }

                    },

                    y: {

                        beginAtZero: true,

                        ticks: {

                            callback: function (value) {
                                return formatNumber(value);
                            }

                        }

                    }

                }

            }

        });

    }


    /* ============================================================
       LIVE TRAFFIC
       ============================================================ */

    async function loadLiveTraffic() {

        try {

            const response = await fetch(
                "/live_data",
                {
                    method: "GET",
                    cache: "no-store",
                    headers: {
                        "Accept": "application/json"
                    }
                }
            );


            if (!response.ok) {

                console.warn(
                    "Live traffic endpoint returned:",
                    response.status
                );

                return;

            }


            const result = await response.json();

            console.log(
                "LIVE TRAFFIC DATA:",
                result
            );


            if (Array.isArray(result)) {
                trafficData = result;
            }

            else if (Array.isArray(result.data)) {
                trafficData = result.data;
            }

            else if (Array.isArray(result.flows)) {
                trafficData = result.flows;
            }

            else if (Array.isArray(result.traffic)) {
                trafficData = result.traffic;
            }

            else {
                trafficData = [];
            }


            currentPage = 1;

            renderTrafficTable();


        } catch (error) {

            console.error(
                "Live traffic error:",
                error
            );

        }

    }


    /* ============================================================
       RENDER TRAFFIC TABLE
       ============================================================ */

    function renderTrafficTable() {

        const tbody = getElement(
            "trafficTableBody",
            "traffic-body",
            "liveTrafficBody"
        );

        if (!tbody) {
            console.warn(
                "Traffic table body not found."
            );
            return;
        }


        tbody.innerHTML = "";


        if (!trafficData || trafficData.length === 0) {

            const row = document.createElement("tr");

            row.innerHTML = `
                <td colspan="6"
                    style="text-align:center;padding:20px;">
                    No live traffic data available.
                </td>
            `;

            tbody.appendChild(row);

            updatePagination(0);

            return;
        }


        const start =
            (currentPage - 1) * ROWS_PER_PAGE;

        const end =
            start + ROWS_PER_PAGE;

        const pageRows =
            trafficData.slice(start, end);


        pageRows.forEach(function (item, index) {

            const row =
                document.createElement("tr");


            const id =
                item.id ||
                item.flow_id ||
                item.flowId ||
                (start + index + 1);


            const source =
                item.source ||
                item.src_ip ||
                item.src ||
                item.source_ip ||
                "-";


            const destination =
                item.destination ||
                item.dst_ip ||
                item.dst ||
                item.destination_ip ||
                "-";


            const protocol =
                item.protocol ||
                "-";


            const application =
                item.application ||
                item.app ||
                item.service ||
                "-";


            row.innerHTML = `

                <td>${escapeHtml(id)}</td>

                <td>${escapeHtml(source)}</td>

                <td>${escapeHtml(destination)}</td>

                <td>${escapeHtml(protocol)}</td>

                <td>${escapeHtml(application)}</td>

                <td>
                    <button
                        class="traffic-action"
                        onclick="inspectTraffic(${start + index})">
                        View
                    </button>
                </td>

            `;


            tbody.appendChild(row);

        });


        updatePagination(
            trafficData.length
        );

    }


    /* ============================================================
       PAGINATION
       ============================================================ */

    function updatePagination(totalRows) {

        const pageElement = getElement(
            "trafficPage",
            "currentPage",
            "pageNumber"
        );

        const previousButton = getElement(
            "previousPage",
            "prevPage",
            "trafficPrevious"
        );

        const nextButton = getElement(
            "nextPage",
            "trafficNext"
        );


        const totalPages =
            Math.max(
                1,
                Math.ceil(
                    totalRows / ROWS_PER_PAGE
                )
            );


        if (pageElement) {

            pageElement.textContent =
                "Page " +
                currentPage +
                " of " +
                totalPages;

        }


        if (previousButton) {

            previousButton.disabled =
                currentPage <= 1;

        }


        if (nextButton) {

            nextButton.disabled =
                currentPage >= totalPages;

        }

    }


    /* ============================================================
       PAGE CONTROLS
       ============================================================ */

    window.previousTrafficPage = function () {

        if (currentPage > 1) {

            currentPage--;

            renderTrafficTable();

        }

    };


    window.nextTrafficPage = function () {

        const totalPages =
            Math.max(
                1,
                Math.ceil(
                    trafficData.length /
                    ROWS_PER_PAGE
                )
            );


        if (currentPage < totalPages) {

            currentPage++;

            renderTrafficTable();

        }

    };


    /* ============================================================
       INSPECT TRAFFIC
       ============================================================ */

    window.inspectTraffic = function (index) {

        if (
            !trafficData ||
            !trafficData[index]
        ) {
            return;
        }


        const item =
            trafficData[index];


        console.log(
            "Traffic details:",
            item
        );


        alert(
            "Traffic Details\n\n" +
            "Source: " +
            (
                item.source ||
                item.src_ip ||
                "-"
            ) +
            "\nDestination: " +
            (
                item.destination ||
                item.dst_ip ||
                "-"
            ) +
            "\nProtocol: " +
            (
                item.protocol ||
                "-"
            ) +
            "\nApplication: " +
            (
                item.application ||
                item.app ||
                "-"
            )
        );

    };


    /* ============================================================
       HTML ESCAPE
       ============================================================ */

    function escapeHtml(value) {

        if (
            value === null ||
            value === undefined
        ) {
            return "";
        }


        return String(value)

            .replace(/&/g, "&amp;")

            .replace(/</g, "&lt;")

            .replace(/>/g, "&gt;")

            .replace(/"/g, "&quot;")

            .replace(/'/g, "&#039;");

    }


    /* ============================================================
       SEARCH TRAFFIC
       ============================================================ */

    function setupTrafficSearch() {

        const searchBox = getElement(
            "trafficSearch",
            "searchTraffic",
            "traffic-search"
        );


        if (!searchBox) {
            return;
        }


        searchBox.addEventListener(
            "input",
            function () {

                const query =
                    searchBox.value
                        .toLowerCase()
                        .trim();


                if (!query) {

                    renderTrafficTable();

                    return;

                }


                const filtered =
                    trafficData.filter(
                        function (item) {

                            return JSON
                                .stringify(item)
                                .toLowerCase()
                                .includes(query);

                        }
                    );


                const original =
                    trafficData;


                trafficData = filtered;

                currentPage = 1;

                renderTrafficTable();

                trafficData = original;

            }
        );

    }


    /* ============================================================
       REFRESH DASHBOARD
       ============================================================ */

    async function refreshDashboard() {

        console.log(
            "Refreshing dashboard..."
        );


        const data =
            await fetchDashboardData();


        if (!data) {

            console.error(
                "No dashboard data received."
            );

            return;

        }


        updateSummary(data);

        updateProtocolChart(data);

        updateApplicationChart(data);

    }


    /* ============================================================
       REFRESH BUTTON
       ============================================================ */

    function setupRefreshButton() {

        const button = getElement(
            "refreshButton",
            "refreshBtn",
            "refresh-dashboard"
        );


        if (!button) {
            return;
        }


        button.addEventListener(
            "click",
            async function () {

                await refreshDashboard();

                await loadLiveTraffic();

            }
        );

    }


    /* ============================================================
       INITIALIZE
       ============================================================ */

    async function initializeDashboard() {

        console.log(
            "========================================"
        );

        console.log(
            "ENTERPRISE DPI DASHBOARD JS"
        );

        console.log(
            "Initializing..."
        );

        console.log(
            "========================================"
        );


        setupTrafficSearch();

        setupRefreshButton();


        await refreshDashboard();

        await loadLiveTraffic();


        /*
         Refresh dashboard every 10 seconds.
        */

        setInterval(
            async function () {

                await refreshDashboard();

                await loadLiveTraffic();

            },
            10000
        );

    }


    /* ============================================================
       START
       ============================================================ */

    if (
        document.readyState ===
        "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            initializeDashboard
        );

    }

    else {

        initializeDashboard();

    }

})();