


var svg,svg2;
var selected;
inputColorScheme="5a";
brushCheck=false;
hideLabels= false;  //hidelabels are used to indicate if student names should be hidden in x axis or not.
function visualizeGraph(){
//inputColorScheme=document.getElementById("inputColorScheme").value;
inputColorScheme=metadata["color-scheme"];

if (document.getElementById("title") != undefined)
	document.getElementById("title").innerHTML =  metadata.title;

if(svg!=null)
  d3.select("#svg").remove();

//=====================================this needs to be replaced later=====================
rankings = []
allrankings = []
stids = []
p=0;
cclen=[]
ccnt=0;
for(var i=0;i<jsonData[0].data.length;i++){
	rankings[i] = []
	for(var j=0;j<jsonData[0].data[i].values.length;j++){
	  stids[i] = jsonData[0].data[i].stuid;
	  rankings[i].push(jsonData[0].data[i].values[j]); //rankings is a multidimensional array with rankings of each student
	  allrankings[p] = jsonData[0].data[i].values[j];  //allrankings is single dimensional array with rankings of each students in order
	  p++;
	}
	rankings[i].rank_avg = jsonData[0].data[i].primary_value; //rank avg corresponds to primary value in json file for each student
	if (jsonData[0].data[i].critcomparer != undefined)
		cclen[i]=jsonData[0].data[i].critcomparer.length;
}
	
		ccarray = [];
		ccstu = [];
		ccvalues = [];
		new_cc = [];
		curval=0;
		ccrit=0;
		flg=0;
		for(var j=0;j<jsonData[0].data.length;j++)
		{
			ccarray[j] = [];
			new_cc[j] = [];
			ccvalues[j] = [];
			ccarray[j][0]=jsonData[0].data[j].stuid;
			new_cc[j][0] = jsonData[0].data[j].stuid;
			ccstu[j]=jsonData[0].data[j].stuid;
			ccvalues[j][0]=jsonData[0].data[j].stuid;
			for(var k=0;k<cclen[j];k++)
			{
				ccvalues[j].push(jsonData[0].data[j].values[k]);
			}
			var tem=0;
			
			for(var k=0;k<cclen[j];k++)
			{
				curval=ccvalues[j][k+1];
				
				for(var ij=0;ij<cclen[j];ij++)
				{
					if(curval==jsonData[0].data[j].critcomparer[ij].rank)
					{
						ccrit=jsonData[0].data[j].critcomparer[ij].critid;
						
						var te =1;
						for(var ji=0;ji<(ccarray[j].length-1);ji++)
						{
							
							
							if(ccrit==ccarray[j][te])
							{flg=1;break;}
						++te;
						
						}
						if(flg==1)
						{
							flg=0;
							continue;
						}
						else
						{
							flg=0;
							ccarray[j].push(jsonData[0].data[j].critcomparer[ij].critid);
							new_cc[j].push(jsonData[0].data[j].critcomparer[ij].critid);
						}
					}
					
				}
				//ccarray[j][tem]=jsonData[0].data[0].critcomparer[tem];
				//ccstu[j].push(jsonData[0].);
				++tem;
			}
		}
	
	
	stcc=[];
	ct=0;
		for(var ij=0;ij<ccarray.length;ij++)
		{
			for(var ji=1;ji<ccarray[ij].length;ji++)
			{
			stcc[ct]=ccarray[ij][0]+'%'+ccarray[ij][ji];
			++ct;
			}
		}
		
			for(var ij=0;ij<ccarray.length;ij++)
		{
			for(var ji=1;ji<ccarray[ij].length;ji++)
			{
			ccarray[ij][ji]=[];
			len = jsonData[0].data[ij].critcomparer[ji-1].otherstu.length;
			while(len>0)
			{
				ccarray[ij][ji].push(jsonData[0].data[ij].critcomparer[ji-1].otherstu[len-1]);
				len--;
			}
			
			}
		}
		
		console.log(ccarray);
		//console.log(ccstu);
		//console.log(ccvalues);
		//console.log(stcc);
		//console.log(new_cc);
		

		
		
		
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

/// flip the y-axis depending on the higher_primary_value_better
primary_vals = rankings.map(function(x){return x.rank_avg});
min_primary_val = metadata['worst-primary-value-possible'] == undefined ? Math.floor(Math.min(...primary_vals)): metadata['worst-primary-value-possible'];
max_primary_val = metadata['best-primary-value-possible'] == undefined ? Math.ceil(Math.max(...primary_vals)): metadata['best-primary-value-possible'];

//if (metadata['higher_primary_value_better']){
//    start_y_scale = min_primary_val-1;
//    end_y_scale = max_primary_val+1;
//}else{
//    start_y_scale = max_primary_val+1;
//    end_y_scale = min_primary_val-1;
//}

    if(metadata['worst-primary-value-possible'] != undefined && metadata['best-primary-value-possible'] != undefined)
        flip = metadata['worst-primary-value-possible'] < metadata['best-primary-value-possible']
    else
        flip = metadata['higher-primary-value-better']

    if (flip)
        y.domain([min_primary_val, max_primary_val]);
    else
        y.domain([max_primary_val, min_primary_val]);
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
stids = [];

p=0;
for(var i=0;i<fextent-f;i++){
  rankings[i] = []
  stids[i] = jsonData[0].data[f+i].stuid;
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
	  .attr("id",function(d,i){ return stids[i];})
	  .attr("class",function(d,i){ return "stutags";})

  
    
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
p5=0;
t=0;
t2=0;
t3=0;
t4=0;
t5=0;
cc=0;
cclen=0;
original_color = ""
//https://coolors.co/browser



    var tooltip = d3.select("body")
        .append("div")
        .style("position", "absolute")
        .style("z-index", "10")
        .style("visibility", "hidden")
        .text(function(d) { return d; });


    bar = svg.selectAll(".bar")
      .data(allrankings)
      .enter().append("rect")
      .attr("class", "bar")
      .attr("x", function(d,i) {
          t3++;
          if(rankings[p3].length==0)p3++;
          if(t3>rankings[p3].length) {
              p3++;
              t3=1;
              return ((width/rankings.length)*(p3));
          }
          return ((width/rankings.length)*(p3));
      })
      .attr("width", function(){
          return width/rankings.length
      })
      .attr("y", function(d,i) {
          t++;
          if(rankings[p].length==0) {
              p++;
              return 0;
          }
          if(t>rankings[p].length) {
              p++;
              t=1;
              return y(rankings[p].rank_avg) + (t-1) * ((height - y(rankings[p].rank_avg))/rankings[p].length);
          }
          return y(rankings[p].rank_avg) + (t-1) * ((height - y(rankings[p].rank_avg))/rankings[p].length);
      })
      .attr("height", function(d,i) {
          t2++;
          //console.log("i =" + i + ", p2 =" + p2)

          if(rankings[p2].length==0) {
              p2++;
              return 0;
          }

          //this piece of sh** causes a rendering bug if it founds 0s. I'm not sure what this is for.
          /*if(d==0) {
              p2++;
              return 100;
          }*/

          if(t2==rankings[p2].length+1) {
              p2++;
              t2=1;
          }

          return (height - y(rankings[p2].rank_avg))/rankings[p2].length - 1
      })
      .style("fill",function(d, i){
          t5++;

          if(t5==rankings[p5].length+1) {
              p5++;
              t5=1;
          }

          color_scale = colorKey[inputColorScheme].length / rankScale
          color_index = (metadata['best-value-possible'] > metadata['worst-value-possible']) ? metadata['best-value-possible'] - d : d - metadata['best-value-possible'];
          //console.log("d: " + d + ", color_idx: " + color_index);
          color = colorKey[inputColorScheme][Math.round(color_index * color_scale)];
          if(metadata["highlight-top-most-bar"] && t5==1)
              color = ColorLuminance(color, 0.3)

          return color;
      })
      .attr("rx",8)
      .attr("ry",8)
      .attr("stuid",function(d,i){
          return stids[i];
      })
      .attr("class","blocks")
      .attr("id",function(d,i){
          return stcc[i];
      })
      .on("mouseover", function(d, i) {
          original_color = this.style.fill
          this.style.fill = "gray";
          tooltip.text(d);
          idFromCircle = this.getAttribute("id");
          //if crit comparer is defined in the json
          if (idFromCircle != null){
            split_id = idFromCircle.split("%");
            critsplitid = split_id[1];

            stags = svg.selectAll(".stutags");
            ih=0;

            for(ih=0;ih < stags[0].length;ih++)
            {
                if(parseInt(stags[0][ih].getAttribute("id")) == critsplitid)
                {
                    stags[0][ih].style.fill = "red";
                    stags[0][ih].style.fontSize  = "15px";
                }
            }

            ccval_len = ccvalues.length;
            tx = 0;
            while(ccval_len>0)
            {
                if(ccvalues[tx][0] == split_id[0])
                {
                    break;
                }
                else{--ccval_len;++tx;}
            }


            ccval_len = ccvalues[tx].length;
            ty = 1;
            while(ccval_len>0)
            {
                if(new_cc[tx][ty] == split_id[1])
                {
                    break;
                }
                else{--ccval_len;++ty;}
            }
            ot_arr = ccarray[tx][ty];

            for(ik=0;ik<ot_arr.length;ik++)
            {
                ih=0;
                stags = svg.selectAll(".stutags");

                for(ih=0;ih < stags[0].length;ih++)
                {
                    if(parseInt(stags[0][ih].getAttribute("id")) == ot_arr[ik])
                    {
                        stags[0][ih].style.fill = "blue";
                        stags[0][ih].style.fontSize  = "15px";
                        stags[0][ih].style.backgroundColor   = "red";

                    }
                }
            }
          }
          return tooltip.style("visibility", "visible");
        })
      .on("mouseout", function(d,i) {

          this.style.fill = original_color;

          idFromCircle = this.getAttribute("id");
          //if crit comparer is defined in the json
          if(idFromCircle != null){
            split_id = idFromCircle.split("%");
            critsplitid = split_id[1];

            stags = svg.selectAll(".stutags");
            ih=0;


            for(ih=0;ih < stags[0].length;ih++)
            {

                        if(parseInt(stags[0][ih].getAttribute("id")) == critsplitid)
                        {

                            stags[0][ih].style.fill = "black";
                            stags[0][ih].style.fontSize  = "10px";

                        }


            }

            ccval_len = ccvalues.length;
            tx = 0;
            while(ccval_len>0)
            {
                if(ccvalues[tx][0] == split_id[0])
                {
                    break;
                }
                else{--ccval_len;++tx;}
            }


            ccval_len = ccvalues[tx].length;
            ty = 1;
            while(ccval_len>0)
            {
                if(new_cc[tx][ty] == split_id[1])
                {
                    break;
                }
                else{--ccval_len;++ty;}
            }
            ot_arr = ccarray[tx][ty];

            for(ik=0;ik<ot_arr.length;ik++)
            {
                ih=0;
                stags = svg.selectAll(".stutags");

                for(ih=0;ih < stags[0].length;ih++)
                {

                            if(parseInt(stags[0][ih].getAttribute("id")) == ot_arr[ik])
                            {

                                stags[0][ih].style.fill = "black";
                                stags[0][ih].style.fontSize  = "10px";
                                stags[0][ih].style.backgroundColor   = "white";

                            }


                }
            }
          }
          return tooltip.style("visibility", "hidden");
     })
      .on("mousemove", function(d, i){
            return tooltip.style("top", (d3.event.pageY-10)+"px").style("left",(d3.event.pageX+10)+"px");
	  })


  svg.select("g")
      .selectAll(".tick")
      .filter(function(d){
		  return d=="" || d.startsWith("/")
	  })  //this is a temporary logic. If our x axis parameter is other than url, then this will change.
      .remove();

}




function type(d) {
  d.rank_avg = +d.rank_avg;
  return d;
}


function ColorLuminance(hex, lum) {

	// validate hex string
	hex = String(hex).replace(/[^0-9a-f]/gi, '');
	if (hex.length < 6) {
		hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
	}
	lum = lum || 0;

	// convert to decimal and change luminosity
	var rgb = "#", c, i;
	for (i = 0; i < 3; i++) {
		c = parseInt(hex.substr(i*2,2), 16);
		c = Math.round(Math.min(Math.max(0, c + (c * lum)), 255)).toString(16);
		rgb += ("00"+c).substr(c.length);
	}

	return rgb;
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


x2.domain(jsonData[0].data.map(function(d,i) {
	if(d.first_name!="")
		return (d.first_name);
	else {
		hideLabels = true;
	}
	return d.column_url;
}));

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
    .attr("y", function(d){
		  if(d.rank_avg==0)
			  return y2(rankScale+0.5);
		  else
			  return y2(d.rank_avg)
	  })
    .attr("height", function(d){
		  if(d.rank_avg==0)
			  return height - y2(rankScale+0.5);
		  if (d.rank_avg!=0)
			  return (height - y2(d.rank_avg));
		  else
			  return 0;
	  })
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
			return (brush.extent()[0] <= x2(d)) && (x2(d) <= brush.extent()[1])
	});
	x.domain(selected);
	visualizeGraph();
}

}
