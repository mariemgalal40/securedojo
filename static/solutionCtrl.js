app.controller("solutionCtrl", function ($scope, $http, $routeParams, dataSvc) {
  var challengeId = $routeParams.challengeId;
  $scope.solutionLink = "challenges/solutions/" + challengeId;
});
