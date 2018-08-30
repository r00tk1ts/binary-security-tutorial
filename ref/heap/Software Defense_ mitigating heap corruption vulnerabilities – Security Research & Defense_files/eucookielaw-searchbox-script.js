        $("#srch-term").keypress(function(event) {
            var n = window.mscc;
            n && !n.hasConsent() && n.setConsent();
        });