package admission

test_allow {
	allow with input as {
        "rules": [
            {
        		"disable": false,
	        	"rule_type": "deny",
		        "criteria": [
			        {
				        "name": "cveHighWithFixCount",
        				"op": ">=",
                        "value": "5",
	        			"sub_criteria": [{
		        			"name": "publishDays",
			        		"op": ">=",
				        	"value": "30",
				        }],
	    		    },
		    	    {
			    	    "name": "namespace",
				        "op": "notContainsAny",
				        "value": "staging",
    		    	},
	    	    ],
	        },
        ]
    }
}

test_not_allow_no_admin_ns {
	not allow with input as {
        "rules": [
            {
        		"disable": false,
	        	"rule_type": "deny",
		        "criteria": [
			        {
				        "name": "cveHighWithFixCount",
        				"op": ">=",
                        "value": "5",
	        			"sub_criteria": [{
		        			"name": "publishDays",
			        		"op": ">=",
				        	"value": "30",
				        }],
	    		    },
	    	    ],
	        },
        ]
    }
}

test_not_allow_no_cve_age {
	not allow with input as {
        "rules": [
            {
        		"disable": false,
	        	"rule_type": "deny",
		        "criteria": [
			        {
				        "name": "cveHighWithFixCount",
        				"op": ">=",
                        "value": "5",
	    		    },
		    	    {
			    	    "name": "namespace",
				        "op": "notContainsAny",
				        "value": "staging",
    		    	},
	    	    ],
	        },
        ]
    }
}