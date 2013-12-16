$(document).ready(function() {
  navigator.id.beginAuthentication(function(email) {
    $("#cancel").click(function(e) {
      e.preventDefault();
      navigator.id.raiseAuthenticationFailure("user canceled authentication");
    });

    $("#login").click(function(e) {
      e.preventDefault();
      navigator.id.completeAuthentication();
    });
  });
});
