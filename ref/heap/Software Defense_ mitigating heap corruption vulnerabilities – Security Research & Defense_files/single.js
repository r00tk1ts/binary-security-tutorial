/**
 * Settings for social share pop up window
 */
(function(window, document, $, undefined) {

	$.fn.msSocialPopup = function( options ) {
		// settings
		var settings = $.extend({
			'popUpWidth'         : 550,  // Width of the Pop-Up Window
			'popUpHeight'        : 450,  // Height of the Pop-Up Window
			'popUpTop'           : 100,  // Top value for Pop-Up Window
			'useCurrentLocation' : false // Whether or not use current location for sharing
		}, options);

		// Attach this plugin to each element in the DOM selected by jQuery Selector and retain statement chaining
		return this.each( function( index, value ) {

			// Respond to click event
			$( this ).on( 'click', function( evt ) {

				evt.preventDefault();

				// Define
				var social = $(this).data( 'social' );

				if ( ! social || ! social.type ) {
					return;
				}

				var left        = Math.round( ( screen.width / 2 ) - ( settings.popUpWidth / 2 ) );
				var socialURL   = settings.useCurrentLocation ? window.location : encodeURIComponent( social.url );
				// var socialImage = encodeURIComponent( social.image );
				var url = '';

				switch( social.type ) {
					case 'facebook':
						url = 'https://www.facebook.com/sharer.php?u='+ socialURL + '&t=' + social.text;
						break;
					case 'twitter':
						url = 'https://twitter.com/share?url='+ socialURL + '&text=' + encodeURIComponent( social.text );
						break;
					case 'linkedin':
						url = 'https://www.linkedin.com/shareArticle?mini=true&url=' + socialURL + '&title=' + encodeURIComponent( social.text );
						break;
				}

				if ( url ) {
					// Google Tag Manager Event
					// If Google Tag Manager js sdk is not loaded,
					// the code below will do nothing but push some
					// JSON data to a global array varible. It should
					// work with a Google Tag Manager WP plugin, such
					// as Metronet Tag Manager, see:
					// https://wordpress.org/plugins/metronet-tag-manager/
					window.dataLayer = window.dataLayer || [];
					window.dataLayer.push({
						'event': 'socialShare', 
						'socialNetwork': 'SocialShareButton', 
						'socialAction': social.type, 
						'socialTarget': social.url
					});

					// Finally fire the Pop-up
					window.open( url, '', 'left='+ left +' , top='+ settings.popUpTop +', width='+ settings.popUpWidth +', height='+ settings.popUpHeight +', personalbar=0, toolbar=0, scrollbars=1, resizable=1' );
				}
			});
		});
	};

	$( function() {
		$('.social-icons-wrap a').msSocialPopup();
	} );

})(window, document, jQuery);
