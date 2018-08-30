
(function() {
    'use strict';
    /**********************************/
    /*********** get-domain ***********/
    /**********************************/
    var homeLink, domain = location.hostname.match(/^[a-z0-9\.]*\.([^.]+\.microsoft\.com[:\d]*)$/);
    if (null === domain || domain.length < 2) {
        homeLink = 'http://www.microsoft.com/';
    } else {
        homeLink = 'http://' + domain[1] + '/';
    }

    document.getElementById('home-link').href = homeLink;

    /**********************************/
    /****** remove empty sidebar ******/
    /**********************************/
    if ( $.trim( $('#secondary').text() ) == '' )
    {
        $('#primary').css("width", "100%");
        $('#secondary').css("display", "none");
    }


    /**********************************/
    /*********** search form **********/
    /**********************************/
    var hostname = location.hostname;
    if (hostname.indexOf("blogs.msdn.microsoft.com") > -1) {
        $("#search-filter-site .search-text").text("Search MSDN");
        $("#search-form").attr("action", "https://social.msdn.microsoft.com/search/en-US");
    }
    else if (hostname.indexOf("blogs.technet.microsoft.com") > -1) {
        $("#search-filter-site .search-text").text("Search TechNet");
        $("#search-form").attr("action", "https://social.technet.microsoft.com/search/en-US");
    }

    $("body").focusin(function (e) {
        if ($(e.target).parents('div#search-form-wrapper').length) {
            $("#search-option").show();
        } else {
            $("#search-option").hide();
        }
    }).click(function (e) {
        if (!$(e.target).parents('div#search-form-wrapper').length) {
            $("#search-option").hide();
        }
    });

    $("#search-option .search-filter").click(function () {
        $("#search-form .form-control").focus();
        var id = $(this).attr('id');
        clearHiddenIpuut();
        $("#search-option .search-filter").each(function (index) {
            if (id == $(this).attr('id')) {
                $(this).addClass("selected");
                switch (id) {
                    case "search-filter-all-blogs":
                        var rn = hostname;
                        var rq = "https://" + hostname;
                        $("#search-form .input-group").prepend("<input type=\"hidden\" name=\"rn\" value=\"" + rn + "\" />");
                        $("#search-form .input-group").prepend("<input type=\"hidden\" name=\"rq\" value=\"site:" + rq + "\" />");
                        break;
                    case "search-filter-this-blog":
                        var homeUrl = $("#search-form").attr("home-url");
                        var rn = homeUrl.substring(homeUrl.lastIndexOf("/") + 1);
                        var rq = homeUrl.replace("https://", "").replace("http://", "");
                        $("#search-form .input-group").prepend("<input type=\"hidden\" name=\"rn\" value=\"" + rn + "\" />");
                        $("#search-form .input-group").prepend("<input type=\"hidden\" name=\"rq\" value=\"site:" + rq + "\" />");
                        break;
                }
            }
            else {
                $(this).removeClass("selected");
            }
        });
    });

    $("#search-option .search-filter").keypress(function (e) {
        if (e.which == 13) {
            $(this).click();
            e.preventDefault();
            return false;
        }
    });
    
    function clearHiddenIpuut() {
        var names = ["rn", "rq"];
        for (var i in names) {
            $("#search-form [name='" + names[i] + "']").remove();
        }
    }

})();