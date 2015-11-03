 <!DOCTYPE html>
<html>
<head>
<script type="text/javascript" src="dojoroot/dojo/dojo.js" djConfig="parseOnLoad: true, isDebug: false"></script>
<script language="JavaScript" type="text/javascript">
	dojo.require("dijit.TitlePane");
	dojo.require("dojo.parser");
	dojo.require("dojo.request");
	dojo.require("dijit.Tooltip");
</script>

<link type="text/css" href="css/style.css" rel="stylesheet" />
<style>
	#progress {
	 width: 500px;   
	 border: 3px solid black;
	 position: relative;
	 padding: 3px;
	}
	
	#bar {
	 height: 20px;
	}
</style>

<script language="JavaScript" type="text/javascript">
require(["dojo/dom", "dojo/on", "dojo/request", "dojo/dom-attr", "dojo/domReady!"],
	    function(dom, on, request, domAttr){
	        // Results will be displayed in resultDiv
	        var resultDiv = dom.byId("results");
	        var strengthDiv = dom.byId("passwordStrength");
	        
	        
	        function updateStrengthBar(strength){
                switch(strength){
                  	case "WEAK":
                  		strengthDiv.innerHTML = "<div id=\"bar\" style=\"background-color: red; width: 2%;\">";
                   		break;
                  	case "MEDIUM":
                   		strengthDiv.innerHTML = "<div id=\"bar\" style=\"background-color: yellow; width: 50%;\">";
                   		break;
                   	case "STRONG":
                   		strengthDiv.innerHTML = "<div id=\"bar\" style=\"background-color: green; width: 100%;\">";
                   		break;
           		 	default:
                   		strengthDiv.innerHTML = "<div id=\"bar\" style=\"background-color: gray; width: 0%;\">";
                   		break;
                } 
                resultDiv.innerHTML = strength;
	        }
 
	        function updateOkButton(strength) {
        		require(['dojo/on', 'dojo/dom', 'dojo/dom-attr'],
				  function (on, dom, domAttr) {
				    var okButton = dom.byId("ok");
				    if(strength === "STRONG") {
				    	domAttr.set(okButton, 'disabled', false);
				    } else {
				    	domAttr.set(okButton, 'disabled', true);
				    }
				});
	        }

	        on(dom.byId("password"), "keyup", function(evt){
	            // Request the text file
	            request.get("/PasswordChecker", 
	            		{
	            			query: {
	            				user: document.getElementById("username").value,
	            				pass: document.getElementById("password").value
	            			}
	            		}).then(
	                function(response){
	                	response = response.trim().toUpperCase();
						updateStrengthBar(response);
						updateOkButton(response);
	                },
	                function(error){
	                    // Display the error returned
	                    alert(error);
	                }
	            );
	        });
	        
	        on(dom.byId("improve"), "click", function(evt){
	            request.get("/ImprovePassword", 
	            	{
	            		query: {
	            			pass: document.getElementById("password").value
	            		}
	            	} ).then(
	                function(response){
	                	newPassword = response.trim();
  						document.getElementById("password").value = newPassword;
  						
  						updateStrengthBar("STRONG");
						updateOkButton("STRONG");
	                },
	                function(error){
	                    // Display the error returned
	                    alert(error);
	                }
	            );
	        });
	    }
	);
</script>

<title>Create Account</title>
</head>

<body>

<div id="container">
	<h1>Create Account</h1>
	<div class="block">
		<input id="username" type="text"/>
		<div id="userDescr" class="default">Enter your username</div>
	</div>
	
	<div class="block">
		<input id="password" type="text"/>
		<div id="passDescr" class="default" >Enter your password</div>
	</div>
	
	<br><br>
	
	<div class="block">
		<div id="passwordStrengthDescr" class="default">Strength of your password</div>
		<div id="passwordStrength">
   			<div id="bar" style="background-color: yellow; width: 0%;">
   		</div>
	</div>
		
	</div>
	
	<div class="block">
		<!-- <div id="resultDescr" class="default">Breakdown of points</div> -->
		<div id="results"></div>
	</div>
	
	<div class="block">
		<button id="improve"  type="button" >Improve your Password</button>
		<button id="ok" dojoType="dijit.form.Button" type="submit" disabled="disabled">OK</button>
	</div>
</div>

</body>

</html>
