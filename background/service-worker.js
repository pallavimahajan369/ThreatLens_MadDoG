console.log("SentinelAI service worker started");


chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        console.log(
            "Service Worker received:",
            message
        );


        if (message.type === "SCAN_RESULT") {

            const scanData = message.data;


            chrome.storage.local.set({

                lastScan: scanData

            });


            console.log(
                "Scan result stored:",
                scanData
            );
        }


        return true;
    }
);