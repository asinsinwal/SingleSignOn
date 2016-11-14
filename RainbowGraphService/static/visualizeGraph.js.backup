
var svg,svg2;
var selected;
inputColorScheme="5a";
brushCheck=false;
hideLabels= false;  //hidelabels are used to indicate if student names should be hidden in x axis or not.

function visualizeGraph(){
    //inputColorScheme=document.getElementById("inputColorScheme").value;
    inputColorScheme=metadata["color-scheme"];

    //document.getElementById("title").innerHTML =  metadata.title;

    if(svg!=null)
      d3.select("#svg").remove();

    //=====================================this needs to be replaced later=====================
    rankings = []
    allrankings = []
    p=0;
    for(var i=0;i<jsonData[0].data.length;i++){
      rankings[i] = []
      for(var j=0;j<jsonData[0].data[i].values.length;j++){
      rankings[i].push(jsonData[0].data[i].values[j]); //rankings is a multidimensional array with rankings of each student
      allrankings[p] = jsonData[0].data[i].values[j];  //allrankings is single dimensional array with rankings of each students in order
      p++;
      }
    rankings[i].rank_avg = jsonData[0].data[i].primary_value; //rank avg corresponds to primary value in json file for each student
    }

    rankScale = Math.abs(metadata['worst-value-possible']-metadata['best-value-possible']) + 1;


    var labels="";

    //Note how all the dimensions are a percentage of the window size. This makes the visualization window size independent.
    //This is very important part of creating a responsive page.
    var margin = {top: 0.1 * window.innerHeight, right: 0.01 * window.innerWidth, bottom: 0.0, left: 0.05 * window.innerWidth},
        width = window.innerWidth*0.9;
        height = (window.innerHeight * 0.6) -  margin.top - margin.bottom;

    y = d3.scale.linear()
        .range([height, 0]);

    yAxis = d3.svg.axis()
        .scale(y)
        .innerTickSize(-width)
        .outerTickSize(0)
        .tickPadding(10)
        .orient("left");

    y.domain([metadata['worst-value-possible']+0.5,metadata['best-value-possible']]);


    //If the user has not use brushing yet, this will make sure that all the students are being shown in the main graph.
    if (brushCheck==false){

        x = d3.scale.ordinal()
        .rangeBands([0, width]);

    xAxis = d3.svg.axis()
        .scale(x)
        .orient("bottom");

    // If no student names are specified in the json file, d3 needs something unique on x-axis to plot the graph.
    // In that case, it would be column_url. Also note that we hideLabels as we dont want to show column_url in this case.
    //TODO: Why does it not require column_url in return statement. It still works if it does not return.
    x.domain(jsonData[0].data.map(function(d,i) {if(d.first_name!="") return (d.first_name); else  return(d.column_url);  }));

    //slider function takes care of building the navigation graph on top of our original graph.
    //slider();
    }

    //=====================================this needs to be replaced later=====================


    if(brushCheck==true){
      f = 0;
      if(selected!=undefined)
        find = selected[0];
      else
        find = 0;
      while(jsonData[0].data[f].column_url!=find && jsonData[0].data[f].first_name!=find){
        f++;
      }

    fextent = 0
    if(selected!=undefined)
      find = selected[selected.length-1];
    else
      find = x.domain()[x.domain().length-1];

    while(jsonData[0].data[fextent].column_url!=find && jsonData[0].data[fextent].first_name!=find)
      fextent++;

    rankings = [];
    allrankings = [];
    p=0;
    for(var i=0;i<fextent-f;i++){
      rankings[i] = []
      for(var j=0;j<jsonData[0].data[f+i].values.length;j++){
      rankings[i].push(jsonData[0].data[f+i].values[j]);
      allrankings[p] = jsonData[0].data[f+i].values[j];
      p++;
      }
    rankings[i].rank_avg = jsonData[0].data[f+i].primary_value;
    }
    }
    //=========================================================================================

     svg = d3.select("body").append("svg")
        .attr("id","svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom+100)
      .append("g")
        .attr("transform", "translate(" + ( margin.left) + "," + (margin.top) + ")")




      svg.append("g")
          .attr("class", "x axis")
          .attr("transform", "translate(0," + height + ")")
          .call(xAxis)
          .selectAll(".tick text")
          .attr("transform", "rotate(-90)")
          .attr("dx",-35)
          .attr("dy",-5)



      //svg.select("g").append("tick")

      svg.append("g")
          .attr("class", "y axis")
          .call(yAxis)
        .append("text")
          .attr("transform", "rotate(-90)")
          .attr("y", -36)
          .attr("x",-(height/2))
          .attr("dy", ".71em")
          .style("text-anchor", "end")
          .text(metadata['y-axis-label']);



    k=0;
    p=0;
    p2=0;
    p3=0;
    p4=0;
    t=0;
    t2=0;
    t3=0;
    t4=0;

    //https://coolors.co/browser



      bar = svg.selectAll(".bar")
          .data(allrankings)
        .enter().append("rect")
          .attr("class", "bar")
          .attr("x", function(d,i) {t3++; if(rankings[p3].length==0){p3++;} if(t3>rankings[p3].length) {p3++; t3=1; return ((width/rankings.length)*(p3));} return ((width/rankings.length)*(p3)); })
          .attr("width", function(){return width/rankings.length})
          .attr("y", function(d,i) { t++; if(rankings[p].length==0) { p++; return 0;} if(t>rankings[p].length) {p++; t=1; return y(rankings[p].rank_avg) + (t-1) * ((height - y(rankings[p].rank_avg))/rankings[p].length);}   return y(rankings[p].rank_avg) + (t-1) * ((height - y(rankings[p].rank_avg))/rankings[p].length);  })
          .attr("height", function(d,i) {  t2++; if(t2==rankings[p2].length+1) {p2++; t2=1;} if(rankings[p2].length==0) { p2++; return 0;} if(d==0) {p2++;  return 100;}   return (height - y(rankings[p2].rank_avg))/rankings[p2].length - 1})
          .style("fill",function(d){
              color_index = (metadata['best-value-possible'] > metadata['worst-value-possible']) ? metadata['best-value-possible'] - d - metadata['worst-value-possible'] : d - metadata['best-value-possible'];
              color_index = Math.round(color_index * colorKey[inputColorScheme].length / rankScale);
              console.log("d: " + d + ", color_idx: " + color_index);
              return colorKey[inputColorScheme][Math.round(color_index)];
          })
          .attr("rx",8)
          .attr("ry",8)
          .on("mouseover", function() { this.style.fill = "gray"; })
         .on("mouseout", function(d,i) {
              color_index = (metadata['best-value-possible'] > metadata['worst-value-possible']) ? metadata['best-value-possible'] - d - metadata['worst-value-possible'] : d - metadata['best-value-possible'];
              color_index = Math.round(color_index * colorKey[inputColorScheme].length / rankScale);
              console.log("d: " + d + ", color_idx: " + color_index);
              this.style.fill = colorKey[inputColorScheme][Math.round(color_index)];
         })


      svg.select("g")
          .selectAll(".tick")
          .filter(function(d){ return d=="" || d.startsWith("/")})  //this is a temporary logic. If our x axis parameter is other than url, then this will change.
          .remove();
}




function type(d) {
  d.rank_avg = +d.rank_avg;
  return d;
}


function slider(){
    
    //Note how percentatges are used to make the navigation graph too responsive with window size.
    //So resizing the window does not crop the graph.

    var margin = {top: 0.0 * window.innerHeight, right: 0.01 * window.innerWidth, bottom: 0.05*window.innerHeight, left: 0.05 * window.innerWidth},
    width = window.innerWidth*0.9;
    var height = (window.innerHeight * 0.2) -  margin.top - margin.bottom;


    // If appending/refreshing slider, remove the one earlier present.
    if(svg2!=null){
      d3.select("#svg2").remove();
}

x2 = d3.scale.ordinal()
    .rangeRoundBands([0, width]);


y2 = d3.scale.linear()
    .range([height, 0]);

xAxis2 = d3.svg.axis()
        .scale(x2)
        .orient("bottom");

//Brush is the rectangular bar that floats on the navigation graph. This is not the call, but just definition of function.
//This function will be called later.
brush = d3.svg.brush()
    .x(x2)
    .extent([0,400])
    .on("brush", brushed)


x2.domain(jsonData[0].data.map(function(d,i) {  if(d.first_name!="") return (d.first_name); else {hideLabels = true;} return d.column_url; }));
y2.domain([rankScale+0.5,0]);

svg2 = d3.select("body").append("svg")
    .attr("id","svg2")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
  .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    svg2.append("g")
      .attr("class", "x axis")
      .attr("transform", "translate(0," + height + ")")
      .call(xAxis2);

svg2.append("rect")
    .attr("class", "grid-background")
    .attr("width", width)
    .attr("height", height);


bar2 = svg2.selectAll(".bar")
      .data(rankings)
    .enter().append("rect")
      .attr("class", "bar")
      .attr("x", function(d,i) { return (width/rankings.length) * i }) //draw the vertical bar at increasing positions.
      .attr("width", width/rankings.length)
      .attr("y", function(d){ if(d.rank_avg==0) return y2(rankScale+0.5); else return y2(d.rank_avg)})
      .attr("height", function(d){ if(d.rank_avg==0) return height - y2(rankScale+0.5); if (d.rank_avg!=0) return (height - y2(d.rank_avg)); else return 0; })
    .style("fill","blue")
    .attr("rx",4)
    .attr("ry",4);


//We don't need any labels on navigator. Remove the labels that come by default.
  svg2.select("g")
      .selectAll(".tick text")
      .remove();

      svg2.select("g")
      .selectAll(".tick")
      .remove();


// We have specified the brush earlier, now it is time to use it to draw it.
var gBrush = svg2.append("g")
    .attr("class", "brush")
    .call(brush); //this will draw the brush - with all the properties of 'brush'

gBrush.selectAll("rect")
    .attr("height", height);


// Selected variable will specify what values are selected by brush
// This will create an array "selected" with values corresponding to x-axis values of students selected on navigation bar.

selected =  x2.domain().filter(function(d){
        //This is being performed for all students because d3 iterates to the length of data
        return (brush.extent()[0] <= x2(d)) && (x2(d) <= brush.extent()[1])
      }
    );                     
      


//This is a nested function only accessible to slider function
function brushed() {
    //d3.event.stopPropagation();
    brushCheck=true;
    if (!d3.event.sourceEvent) return;
          selected =  x2.domain().filter(function(d){
            return (brush.extent()[0] <= x2(d)) && (x2(d) <= brush.extent()[1])});
          x.domain(selected);
          visualizeGraph();



    }

}
