// ------------------------------------
// Get current active tab
// ------------------------------------

chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },
    (tabs) => {

        if (!tabs || !tabs.length) {

            return;
        }


        const tab = tabs[0];


        // Display current URL

        document.getElementById(
            "currentUrl"
        ).textContent =
            tab.url || "Unknown";


        // Get latest scan

        chrome.storage.local.get(
            "lastScan",
            (result) => {

                const scan = result.lastScan;


                if (!scan) {

                    return;
                }


                // Website finding count

                document.getElementById(
                    "websiteFindings"
                ).textContent = 0;


                // Extension finding count

                document.getElementById(
                    "extensionFindings"
                ).textContent = 0;


                // For Phase 2 foundation,
                // page is currently considered low risk

                document.getElementById(
                    "riskLevel"
                ).textContent =
                    "LOW RISK";


                document.getElementById(
                    "riskIcon"
                ).textContent =
                    "🟢";
            }
        );
    }
);


// ------------------------------------
// View Details
// ------------------------------------

document.getElementById(
    "detailsBtn"
).addEventListener(
    "click",
    () => {

        alert(
            "Detailed security findings will be available in the next phase."
        );

    }
);


// ------------------------------------
// Dashboard
// ------------------------------------

document.getElementById(
    "dashboardBtn"
).addEventListener(
    "click",
    () => {

        alert(
            "Security dashboard will be implemented later."
        );

    }
);