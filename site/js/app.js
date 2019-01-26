var leave_nav_set = false;
// For first parsing location.hash when a user visits a link
var first_url_hash = window.location.hash.toString();

// Remove clickability of logo
$(".tarnish-logo").click(function( event ) {
	event.preventDefault();
});

// Indicates if a user has navigated at all since the page loaded.
var user_has_navigated_since_page_load = false;

Vue.directive('highlightjs', {
	deep: true,
	bind: function(el, binding) {
		// on first bind, highlight all targets
		let targets = el.querySelectorAll('code')
		targets.forEach((target) => {
			// if a value is directly assigned to the directive, use this
			// instead of the element content.
			if (binding.value) {
				target.textContent = binding.value
			}
			hljs.highlightBlock(target)
		})
	},
	componentUpdated: function(el, binding) {
		// after an update, re-fill the content and then highlight
		let targets = el.querySelectorAll('code')
		targets.forEach((target) => {
			if (binding.value) {
				target.textContent = binding.value
				hljs.highlightBlock(target)
			}
		})
	}
})

var app = new Vue({
	el: "#main",
	data: {
		view_file_filename: "",
		view_file_contents: "",
		view_file_type: "text",
		extension_zip_data: false,
		extension_id: false,
		extension_loaded: false,
		menu: "unstarted",
		extension_name: "Untitled Extension",
		report_data: {},
		visible_risky_javascript_functions: [],
		visible_web_entrypoints: [],
		static_risky_javascript_functions: [],
		static_web_entrypoints: [],
	},
	methods: {
		initialize_visible: function(event) {
			var filterables = ["risky_javascript_functions", "web_entrypoints"];
			for (var q = 0; q < filterables.length; q++) {
				var indicator_names_array = [];
				for (var i = 0; i < app.report_data[filterables[q]].length; i++) {
					var current_name = app.report_data[filterables[q]][i].indicator.name;
					if (!indicator_names_array.includes(current_name) && current_name != "") {
						indicator_names_array.push(current_name);
					}
				}
				this["visible_" + filterables[q]] = indicator_names_array;
				this["static_" + filterables[q]] = indicator_names_array;
			}
		},
		hide_visible: function(event) {
			console.log("Hide visible event: ");
			var visible_class = event.srcElement.getAttribute("filterclass");
			var indicator_name = event.srcElement.getAttribute("name");
			console.log("Class: " + visible_class + " Name: " + indicator_name);
			this["visible_" + visible_class] = this["visible_" + visible_class].filter(function(e) {
				return e !== indicator_name
			});
			menu_update();
		},
		show_visible: function(event) {
			console.log("Show visible event: ");
			var visible_class = event.srcElement.getAttribute("filterclass");
			var indicator_name = event.srcElement.getAttribute("name");
			console.log("Class: " + visible_class + " Name: " + indicator_name);
			this["visible_" + visible_class].push(
				indicator_name
			);
			console.log(this["visible_" + visible_class]);
			menu_update();
		},
		view_file: function( event ) {
			var current_target = event.target;
			var file_path = current_target.getAttribute( "path" );
			while( file_path == null ) {
				current_target = current_target.parentElement;
				file_path = current_target.getAttribute( "path" );
			}

			if( !file_path ) {
				alert( "Could not pull file from client ZIP archive." );
				return false;
			}

			console.log( "Viewing file path " + file_path );

			view_extension_file_contents(
				file_path
			);
		},
		close_file: function() {
			if( user_has_navigated_since_page_load ) {
				history.back();
			} else {
				app.menu = "manifest";
				menu_update();
			}
		}
	}
});

function analyze_chrome_extension(extension_id) {
	return new Promise(function(resolve, reject) {
		var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
			if (xhr.readyState == XMLHttpRequest.DONE) {
				resolve(
					JSON.parse(
						xhr.responseText
					)
				);
			}
		}
		xhr.onerror = function() {
			reject();
		}
		if( window.location.toString().indexOf( "localhost" ) !== -1 ) {
			xhr.open(
				"POST",
				"http://localhost:80",
				true
			);
		} else {
		xhr.open(
				"POST",
				"https://tarnish.thehackerblog.com/",
				true
			);
		}
		xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
		xhr.send(
			JSON.stringify({
				"extension_id": extension_id,
			})
		);
	});
}

// Detect enter press in extension input box
$(".chrome-extension-input").keypress(function(e) {
	if (e.which == 13) {
		start_extension_analysis();
	}
});

$(".start-scan-button").click(function() {
	start_extension_analysis();
});

function add_leave_nav_warning() {
	if (!leave_nav_set) {
		// Prevent people from losing their page
		window.addEventListener("beforeunload", function(e) {
			var confirm = "Sorry to bother, are you sure you want to navigate away? You'll lose the currently loaded extension.";
			(e || window.event).returnValue = confirm;
			return confirm;
		});
	}
	leave_nav_set = true;
}

function start_extension_analysis() {
	$( ".chrome-extension-input" ).blur();
	var chrome_extension_input_value = $(".chrome-extension-input").val();
	var chrome_id_matches = chrome_extension_input_value.match(/[a-z]{32}/g);
	if (chrome_id_matches && chrome_id_matches.length > 0) {
		var chrome_extension_id = chrome_id_matches[0];
		load_extension_id( chrome_extension_id ).then(function() {
			app.menu = "manifest";
			menu_update();
		});
	} else {
		alert("Invalid Chrome extension input!");
	}
}

function load_extension_id( chrome_extension_id ) {
	$(".chrome-extension-input").val("");
	app.menu = "analyzing-extension-load-screen";
	// Set our extension loaded value back to false
	app.extension_loaded = false;
	app.extension_name = "Untitled Extension";
	return analyze_chrome_extension(
		chrome_extension_id
	).then(function(response_data) {
		// Set navigate away warning
		add_leave_nav_warning();
		// Set extension ID
		app.extension_id = response_data.extension_id;

		// Set report data
		app.report_data = response_data;
		// Set extension name
		app.extension_name = app.report_data.manifest.name;

		// Dark magic
		return new Promise(function (resolve, reject) {
			Vue.nextTick(function () {
				return initialize().then(function() {
					resolve();
				});
			});
		});
		
	}, function(error) {
		alert("An error occured while attempting to scan this extension!");
		location.reload();
		return Promise.reject();
	});
}

// Constantly update feather icons to combat bug with Vue integration
// Hacky, but low cost.
setInterval(function() {
	// Re-add feather icons
	feather.replace();
}, 500);

function menu_update() {
	// Update pushstate
	update_pushstate();

	window.scrollTo( 0, 0 );

	// Initialize clipboard copy buttons
	// copy_fingerprint_js_button
	var new_clipboard = new ClipboardJS( ".clipboard-copy" );
}

function update_pushstate() {
	var hash_object = {
		"menu": app.menu.toString(),
		"extension_id": app.extension_id.toString(),
	};

	// Handle edge case of viewing a file
	if( app.view_file_filename && hash_object[ "menu" ] == "view-file" ) {
		hash_object[ "filename" ] = app.view_file_filename;
	}

	var new_hash = "#" + JSON.stringify( hash_object );
	if( new_hash != decodeURI( window.location.hash.toString() ) ) {
		// We now set this variable to false since the user has navigates somewhere
		user_has_navigated_since_page_load = true;
		console.log( "Pushing new state: " + new_hash );
		history.pushState(
			null,
			null,
			new_hash // Make more friendly links
		);
	}
}

function get_url_hash_object( input_hash ) {
	try {
		var hash_object = JSON.parse( decodeURI( input_hash ).substring(1) );
	} catch ( e ) {
		console.log( "Exception whilst parsing hash: " );
		console.log( "Raw hash: " );
		console.log( input_hash );
		console.log( "Exception: " );
		console.log( e );
		return false;
	}
	return hash_object;
}

function load_url_state_change( input_hash ) {
	var hash_object = get_url_hash_object( input_hash );

	if( !hash_object ) {
		return false;
	}

	if( "extension_id" in hash_object && hash_object[ "extension_id" ] != "false" && hash_object[ "extension_id" ] != app.extension_id ) {
		var extension_load_promise = load_extension_id( hash_object[ "extension_id" ] );
	}

	// Wait to update menu from hash
	if( extension_load_promise ) {
		extension_load_promise.then(function() {
			update_menu_from_hash( hash_object );
		});
	} else {
		update_menu_from_hash( hash_object );
	}
	return true;
}

// Change menu based on hash
function update_menu_from_hash( hash_object ) {
	console.log( "Updating menu..." );
	if( "menu" in hash_object && hash_object[ "menu" ] != "false" && hash_object[ "menu" ] != app.menu ) {
		app.menu = hash_object[ "menu" ];
	}

	if( "filename" in hash_object && hash_object[ "filename" ] != "false" && hash_object[ "filename" ] != app.view_file_filename ) {
		view_extension_file_contents(
			hash_object[ "filename" ]
		);
	}
}

// Listen for hash changes
$( window ).on( "hashchange", function() {
	console.log( "User has navigated to a new hash..." );
	load_url_state_change(
		window.location.hash
	);
});

// Listen for hash changes
$( window ).ready(function() {
	console.log( "User has navigated to a new hash..." );
	load_url_state_change(
		window.location.hash
	);
});

function generate_blob_uri( mime_type, blob_content ) {
	var new_blob = new Blob( [ blob_content ], { type : mime_type } );
	return URL.createObjectURL( new_blob );
}

function get_binary_data( input_url ) {
	return new Promise(function( resolve, reject ) {
		var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
			if (xhr.readyState == XMLHttpRequest.DONE) {
				resolve(xhr.response);
			}
		}
		xhr.open(
			"GET",
			input_url,
			true
		);
		xhr.responseType = "arraybuffer";
		xhr.send(null);
	});
}

function view_extension_file_contents( file_path ) {
	var image_exts = [
		"png",
		"jpg",
		"jpeg",
		"gif",
		"tiff"
	];
	var file_extension = "";
	app.view_file_type = "text";
	// Iterate over image extensions, if it's an image then set the viewer to that
	for( var i = 0; i < image_exts.length; i++ ) {
		if( file_path.endsWith( "." + image_exts[i] ) ) {
			app.view_file_type = "image";
			file_extension = image_exts[i];
		}
	}
	app.view_file_filename = file_path;
	var zip_extract_type = "string";

	if( app.view_file_type === "image" ) {
		zip_extract_type = "uint8array"
	}

	app.extension_zip_data.file(
		file_path
	).async( zip_extract_type ).then(function( contents ) {
		if( app.view_file_type === "text" ) {
			app.view_file_contents = contents;
		} else {
			app.view_file_contents = generate_blob_uri( "image/" + file_extension, contents );
		}
		app.menu = "view-file";
		menu_update();
		Vue.nextTick(function() {
			window.scrollTo( 0, 0 );
		});
	});
}

function _initialize() {
	console.log("App initialized!");

	app.initialize_visible();

	// Set extension loaded status
	app.extension_loaded = true;

	/*
	// Load URL path if there is one, else default.
	var hash_exists = load_url_state_change(
		first_url_hash
	);
	*/

	console.log( "Load URL state change" );

	Vue.nextTick(function() {
		$(".known-vulnerable-libraries-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "known-vulnerable-libraries";
			menu_update();
		});

		$(".manifest-viewer-link-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "manifest";
			menu_update();
		});

		$(".permissions-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "permissions";
			menu_update();
		});

		$(".fingerprintable-resources-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "fingerprintable-resources";
			menu_update();
		});

		$(".dangerous-functions-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "dangerous-functions";
			menu_update();
		});

		$(".manifest-viewer-link-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "manifest";
			menu_update();
		});

		$(".entry-points-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "entry-points";
			menu_update();
		});

		$(".csp-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "csp";
			menu_update();
		});

		$(".potential-clickjacking-nav").click(function( event ) {
			event.preventDefault();
			app.menu = "potential-clickjacking";
			menu_update();
		});

		//menu_update();
	});
}

function initialize() {
	app.menu = "pulling-zip-load-screen";

	// Pull extension zip file
	console.log( "Pulling in the extension zip..." );
	return get_binary_data( 
		app.report_data.s3_beautified_extension_download_link,
	).then(function( zip_data_array_buffer ) {
		return JSZip.loadAsync( zip_data_array_buffer );
	}).then(function( zip_object ) {
		app.extension_zip_data = zip_object;
		// Now make everything visible
		_initialize();
		return Promise.resolve();
	});
}

//menu_update();
