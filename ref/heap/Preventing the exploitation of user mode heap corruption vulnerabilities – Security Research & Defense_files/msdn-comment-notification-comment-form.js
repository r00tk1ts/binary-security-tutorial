$(window).load(function(){
    $('#submit').click(function(){
        $(this).animate({
            width:$(this).css('height'),
            height:$(this).css('height'),
            borderRadius:$(this).css('height'),
            borderLeftWidth:'0',
            fontSize:'0'
        },700,function(){
            $(this).addClass('cssload-speeding-wheel');
        });
    });
    $('#commentform').submit(function(){
        $('#submit').prop('disabled', true);
    })
});