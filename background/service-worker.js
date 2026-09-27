console.log("SentinelAI service worker started");

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        console.log(
            "Service Worker received:",
            message
        );

        if (message.type === "SCAN_RESULT") {

            const tabId = sender.tab?.id;

            if (tabId === undefined) {
                return;
            }

            chrome.storage.local.set({

                lastScan: message.data,

                [`scan_${tabId}`]: message.data

            });

            console.log(
                "Scan result stored for tab:",
                tabId
            );
        }

    }
);