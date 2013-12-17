$(document).ready(function() {
  navigator.id.beginAuthentication(function(email) {
    window.location = '/login';
  });
});
