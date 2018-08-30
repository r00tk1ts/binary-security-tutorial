function deleteEvent(element){
    var $ = jQuery.noConflict();
    var ajax_params = wpAjax.unserialize(element.attributes["url"].value);
    
    $.post( element.attributes["url"].value, {
        action: 'sce_delete_comment',
        comment_id: ajax_params.comment_id, 
        post_id: ajax_params.post_id,
        nonce: ajax_params._wpnonce
    })
    .done( function(msg) {
        if (msg == '') {
            // When the request completes, reload the window.
            window.location.reload();
        } else {
            alert( msg );
        }
    });
}