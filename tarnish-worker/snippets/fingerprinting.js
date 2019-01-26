var fingerprint_cache = {};

function extension_id_from_uri( input_uri ) {
	input_uri = input_uri.replace( "chrome-extension://", "" );
	var parts = input_uri.split( "/" );
	if( parts.length > 0 ) {
		return parts[0];
	}
	return false;
}

function start_fingerprinting( fingerprint_resource_data ) {
	var head = document.getElementsByTagName( "head" )[0];

	fingerprint_cache[ fingerprint_resource_data.extension_id ] = {
		"callback": fingerprint_resource_data.callback,
		"resources": {},
	}
	for( var i = 0; i < fingerprint_resource_data.resources.length; i++ ) {
		fingerprint_cache[ fingerprint_resource_data.extension_id ][ "resources" ][ fingerprint_resource_data.resources[i].resource ] = false;
	}

	for( var i = 0; i < fingerprint_resource_data.resources.length; i++ ) {
		var new_link_elem = document.createElement( "link" );
		new_link_elem.setAttribute( "rel", "stylesheet" );
		new_link_elem.setAttribute( "type", "text/css" );
		new_link_elem.setAttribute( "href", fingerprint_resource_data.resources[i].resource );
		new_link_elem.onload = function() {
			var extension_id = extension_id_from_uri( this.href );
			var resource_path = this.href;

			fingerprint_cache[ extension_id ][ "resources" ][ resource_path ] = true;

			var fingerprint_successful = true;
			for( var key in fingerprint_cache[ extension_id ][ "resources" ] ) {
				if( fingerprint_cache[ extension_id ][ "resources" ].hasOwnProperty( key ) && fingerprint_cache[ extension_id ][ "resources" ][ key ] === false ) {
					fingerprint_successful = false;
					break;
				}
			}
			if( fingerprint_successful ) {
				fingerprint_cache[ extension_id ][ "callback" ]();
			}
		}
		head.appendChild(new_link_elem);
	}
}

function start() {
	start_fingerprinting(
		extension_fingerprint_resources
	);
}

// https://stackoverflow.com/a/807997
if( window.attachEvent ) {
    window.attachEvent( "onload", start );
} else {
    if( window.onload ) {
        var curronload = window.onload;
        var newonload = function( evt ) {
            curronload( evt );
            start( evt );
        };
        window.onload = newonload;
    } else {
        window.onload = start;
    }
}