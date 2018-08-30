/**
 * front widget scripts
 * author Lucy Tomás
 * @since 3.1
 */


jQuery(document).ready(function($) {


	var sfmsb_widget = new sfmsb_front();
	sfmsb_widget.init_icons();
	
});



// Closure

function sfmsb_front (){
	
	return {

		/**
		 * init_icons
		 * inits hover color effect
		 */

		init_icons : function () {

			jQuery('.sfmsb-follow-social-buttons a').hover( 

				function(){
					var hover_color = jQuery(this).parent('.sfmsb-follow-social-buttons').attr('data-hover');
					jQuery(this).find('span').css('color', hover_color);
				}, 
				function(){
					jQuery(this).find('span').css('color', jQuery(this).find('span').attr('data-color'));
				} 

			);

		}

	} // 

}


 

