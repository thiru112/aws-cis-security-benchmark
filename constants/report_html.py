html = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>AWS CIS Benchmark Results</title>
    <link
      rel="stylesheet"
      href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css"
      integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk"
      crossorigin="anonymous"
    />
  </head>
  <body>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark">
      <a class="navbar-brand" href="#">AWS CIS Benchmark Report</a>
      <button
        class="navbar-toggler"
        type="button"
        data-toggle="collapse"
        data-target="#navbarsExample04"
        aria-controls="navbarsExample04"
        aria-expanded="false"
        aria-label="Toggle navigation"
      >
        <span class="navbar-toggler-icon"></span>
      </button>

      <div class="collapse navbar-collapse" id="navbarsExample04">
        <ul class="navbar-nav mr-auto">
          <li class="nav-item active">
            <a class="nav-link" href="#">Report</a>
          </li>
          <li class="nav-item">
            <a
              class="nav-link"
              href="https://github.com/thiru112/aws-cis-security-benchmark"
              target="_blank"
              >GitHub</a
            >
          </li>
        </ul>
      </div>
    </nav>
    <div class="container mt-2">
      <div class="row">
        <div class="col-md">
          <canvas id="myChart1"></canvas>
        </div>
        <div class="col-md">
          <canvas id="myChart2"></canvas>
        </div>
      </div>
      <div class="row">
        <div class="col-md">
          <canvas id="myChart3"></canvas>
        </div>
        <div class="col-md">
          <canvas id="myChart4"></canvas>
        </div>
      </div>
      <div class="table-responsive mt-4">
        <table class="table">
          <thead>
            <tr>
              <th scope="col">Section</th>
              <th scope="col">Scoring Information</th>
              <th scope="col">Result</th>
              <th scope="col">Description</th>
              <th scope="col">Fail reason</th>
              <th scope="col">Offenders</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </body>
  <script>
    var data_section = """
html2 = """
  </script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@2.8.0"></script>
  <script>
    // var ctx = document.getElementById('myChart').getContext('2d');
    var myChart1 = new Chart(document.getElementById("myChart1"), {
      type: "doughnut",
      data: {
        labels: ["Pass", "Fail", "Not Assessed"],
        datasets: [
          {
            label: "Section 1",
            data: data_section.iam_res,
            backgroundColor: ["#2ecc71", "#ff0000", "#f1c40f"],
          },
        ],
      },
      options: {
        legend: {
          position: "bottom",
        },
        title: {
          display: true,
          text: "Identity and Access Management",
          fontSize: 20,
          fontColor: "#000",
        },
      },
    });
    var myChart2 = new Chart(document.getElementById("myChart2"), {
      type: "doughnut",
      data: {
        labels: ["Pass", "Fail", "Not Assessed"],
        datasets: [
          {
            label: "Section 2",
            data: data_section.log_res,
            backgroundColor: ["#2ecc71", "#ff0000", "#f1c40f"],
          },
        ],
      },
      options: {
        legend: {
          position: "bottom",
        },
        title: {
          display: true,
          text: "Logging",
          fontSize: 20,
          fontColor: "#000",
        },
      },
    });
    var myChart3 = new Chart(document.getElementById("myChart3"), {
      type: "doughnut",
      data: {
        labels: ["Pass", "Fail", "Not Assessed"],
        datasets: [
          {
            label: "Section 3",
            data: data_section.mon_res,
            backgroundColor: ["#2ecc71", "#ff0000", "#f1c40f"],
          },
        ],
      },
      options: {
        legend: {
          position: "bottom",
        },
        title: {
          display: true,
          text: "Monitoring",
          fontSize: 20,
          fontColor: "#000",
        },
      },
    });
    var myChart4 = new Chart(document.getElementById("myChart4"), {
      type: "doughnut",
      data: {
        labels: ["Pass", "Fail", "Not Assessed"],
        datasets: [
          {
            label: "Section 4",
            data: data_section.net_res,
            backgroundColor: ["#2ecc71", "#ff0000", "#f1c40f"],
          },
        ],
      },
      options: {
        legend: {
          position: "bottom",
        },
        title: {
          display: true,
          text: "Networking",
          fontSize: 20,
          fontColor: "#000",
        },
      },
    });
  </script>
  <script
    src="https://code.jquery.com/jquery-3.5.1.slim.min.js"
    integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj"
    crossorigin="anonymous"
  ></script>
  <script>
    $(function(){
      $.each(output, function(key, value){
        if (value.result == true){
          $("tbody").append('<tr  class="table-success"><td>'+value.control_id+'</td>'+'<td>'+value.scored+'</td>'+'<td>'+'Passed'+'</td>'+'<td>'+value.desc+'</td>'+'<td>'+value.fail_reason+'</td>'+'<td>'+value.offenders+'</td>');
        }
        if (value.result == false){
          $("tbody").append('<tr  class="table-danger"><td>'+value.control_id+'</td>'+'<td>'+value.scored+'</td>'+'<td>'+'Fail'+'</td>'+'<td>'+value.desc+'</td>'+'<td>'+value.fail_reason+'</td>'+'<td>'+value.offenders+'</td>');
        }
        if (value.result == null){
          $("tbody").append('<tr  class="table-warning"><td>'+value.control_id+'</td>'+'<td>'+value.scored+'</td>'+'<td>'+'Not assessed'+'</td>'+'<td>'+value.desc+'</td>'+'<td>'+value.fail_reason+'</td>'+'<td>'+value.offenders+'</td>');
        }
      });
    });
  </script>
  <script
    src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js"
    integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo"
    crossorigin="anonymous"
  ></script>
  <script
    src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"
    integrity="sha384-OgVRvuATP1z7JjHLkuOU7Xw704+h835Lr+6QL9UvYjZE3Ipu6Tp75j7Bh/kR0JKI"
    crossorigin="anonymous"
  ></script>
</html>
"""