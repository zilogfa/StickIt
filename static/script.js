// alert("Hello from JavaScript")


// let popup = document.getElementById("popup");
// let bgBlur = document.getElementById("bg-blur");

// function openPopup(idNum){
//     idList.push(idNum)
//     bgBlur.classList.add("bg-blur");
//     popup.classList.add("open-popup");
    
// };

// function closePopup(){
//     popup.classList.remove("open-popup");
//     bgBlur.classList.remove("bg-blur");
// };





$(document).ready(function() {
    $('.delete-btn').click(function(e) {
        e.preventDefault();
        var postId = $(this).data('post-id');
        var result = confirm("Are you sure you want to delete this task?");
        
        if (result) {
            $.ajax({
                url: '/delete/' + postId,
                type: 'POST',
                success: function(response) {
                    window.location.reload();
                },
                error: function(error) {
                    console.log(error);
                }
            });
        }
    });
});

