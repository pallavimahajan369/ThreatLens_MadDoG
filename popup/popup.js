document.getElementById("dashboardBtn").addEventListener(
    "click",
    () => {

        chrome.tabs.query(
            {
                active: true,
                currentWindow: true
            },
            (tabs) => {

                if (!tabs || !tabs.length) {
                    return;
                }

                const currentTab = tabs[0];

                const dashboardUrl =
                    chrome.runtime.getURL(
                        "dashboard/dashboard.html"
                    ) +
                    "?tabId=" +
                    currentTab.id +
                    "&url=" +
                    encodeURIComponent(
                        currentTab.url || ""
                    );

                chrome.tabs.create({
                    url: dashboardUrl
                });

            }
        );

    }
);