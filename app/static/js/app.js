/* Add your Application JavaScript */
const app = angular.module('project2', []);

app.controller('project2Controller', function ($scope, $http) {
  $scope.result = 'The result will appear here.';
  $scope.token = '';

  // Usually the generation of a JWT will be done when a user either registers
  // with your web application or when they login.
  $scope.getToken = function() {
    $http.get('/token')
      .then(function(response) {
        jwt_token = response.data.data.token;

        // We store this token in localStorage so that subsequent API requests
        // can use the token until it expires or is deleted.
        localStorage.setItem('token', jwt_token);
        console.log('Token generated and added to localStorage.');
        $scope.token = jwt_token;
      });
  };

  // Remove token stored in localStorage.
  // Usually you will remove it when a user logs out of your web application
  // or if the token has expired.
  $scope.removeToken = function() {
    localStorage.removeItem('token');
    console.info('Token removed from localStorage.');
    alert('Token removed!');
  };

  // The /api/secure route requires a JWT token be sent via an Authorization
  // header. JWT also uses the 'Bearer' schema.
  $scope.getSecure = function() {
    $http.get('/api/users/<int:userid>/wishlist', {
      'headers': {
        'Authorization': 'Basic ' + localStorage.getItem('token')
      }
    }).then(function(response) {
      alert = document.querySelector('.alert');
      alert.classList.remove('alert-info', 'alert-danger');
      alert.classList.add('alert-success');

      result = response.data;
      // successful response
      $scope.result = "success !";
    }, function(response) {
      alert = document.querySelector('.alert');
      alert.classList.remove('alert-info');
      alert.classList.add('alert-danger');

      // unsuccessful response (ie. there was an error)
      $scope.result = "There was an error. ${response.data.description}";
    });
  };

});