var popupIsOpen = false;

function myPopupWin(windowLocation, cb = () => { }) {

    if (! popupIsOpen)
    {
        popupIsOpen = true;

        if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
            var width = 1;
            var height = .97;
        }
        else {
            var width = 0.95;
            var height = .97;
        }


        $('html, body').addClass('no_scroll');

        $.colorbox({
            iframe: true,
            speed: 200,
            title: false,
            width: $(window).width() * width,
            height: $(window).height() * height,
            href: windowLocation,
            //overlayClose: false,
            //closeButton: false,
            onClosed: function () {	
                console.log(windowLocation);	
                popupIsOpen = false;	
                cb();
                $(".modal-backdrop.in").remove();
                $('html, body').removeClass('no_scroll');
                $(".cboxElement").removeClass("cboxElement")                
                if(windowLocation.includes('edit') || windowLocation.includes('Edit') || windowLocation.includes('view') || windowLocation.includes('View')){                 
                    $.ajax({
                        type:'POST',
                        url: `/${ globalVariables.routLink }/edit_case_delete`,
                        data: {},
                        success: function(data){
                        }
                    });
                }
            }
        });
        
       /*
        $('.iframe').colorbox({
            iframe: true,
            speed: 200,
            title: false,
            width: $(window).width() * width,
            height: $(window).height() * height,
            href: windowLocation,
            //overlayClose: false,
            //closeButton: false,
            onClosed: function () {		
                popupIsOpen = false;	
                cb();
                $(".modal-backdrop.in").remove();
                $('html, body').removeClass('no_scroll');
                $(".cboxElement").removeClass("cboxElement") 			
                
            }
        });
        */
    }
}


