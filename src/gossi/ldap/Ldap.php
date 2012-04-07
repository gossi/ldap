<?php
namespace gossi\ldap;

/**
 * LDAP encapsulation to connect and bind to servers. Offers:
 * 
 * <ul>
 * 	<li>Add</li>
 *  <li>Modify/Update</li>
 *  <li>Delete</li>
 *  <li>Rename/Move</li>
 *  <li>Search</li>
 * </ul>
 *
 * @author Thomas Gossmann
 */
class Ldap {
	private $conn;

	/**
	 * Adds an entry to the LDAP directory.
	 * 
	 * @param String $dn The distinguished name of a LDAP entity.
	 * @param array $attribs An array that specifies the information about the entry. The values in the entries are indexed by individual attributes. In case of multiple values for an attribute, they are indexed using integers starting with 0.
	 */
	public function add($dn, $attribs) {
		return ldap_add($this->conn, $dn, $attribs);
	}

	/**
	 * Binds the ldap connection to the provided credentials.
	 * 
	 * @throws \gossi\ldap\LdapException If the bind fails.
	 * @param String $dn The distinguished name of a LDAP entity.
	 * @param String $password the password to the DN.
	 * @return boolean Returns true on success or false on failure.
	 */
	public function bind($dn, $password) {
		$success = @ldap_bind($this->conn, $dn, $password);
		if (ldap_errno($this->conn)) {
			throw new LdapException(ldap_error($this->conn), ldap_errno($this->conn));
		}
		return $success;
	}

	/**
	 * Connects to the provided server and port. LDAP protocol version is set to 3.
	 * 
	 * @param String $server The server address.
	 * @param int $port The port to that server address.
	 */
	public function connect($server, $port = 389) {
		$this->conn = @ldap_connect($server, $port);

		@ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		@ldap_set_option($this->conn, LDAP_OPT_REFERRALS, 0);
	}

	/**
	 * Closes the server connection.
	 * 
	 * @return boolean Returns true on success and false on failure.
	 */
	public function close() {
		return @ldap_unbind($this->conn);
	}

	/**
	 * Deletes an entry at the given DN.
	 * 
	 * @param String $dn The distinguished name of a LDAP entity.
	 * @return boolean Returns true on success and false on failure.
	 */
	public function delete($dn) {
		return ldap_delete($this->conn, $dn);
	}

	/**
	 * A helper function to espace strings.
	 * 
	 * @param String $string The unescaped String
	 * @return String The escaped String
	 */
	public static function escape($string) {
		return str_replace(
			array('*', '\\', '(', ')'),
			array('\\*', '\\\\', '\\(', '\\)'),
			$string
		);
	}

	/**
	 * Generates a password to store in a LDAP directory.
	 * 
	 * @param String $password a plain password
	 * @return String the hashed password
	 */
	public static function generatePassword($password) {
		return '{SHA}'.base64_encode(pack("H*", sha1($password)));
	}

	/**
	 * Updates a LDAP entity at the given DN with the provided attributes.
	 * 
	 * @param String $dn The distinguished name.
	 * @param array $attribs The new attributes.
	 * @return boolean Returns true on success or false on failure.
	 */
	public function modify($dn, $attribs) {
		return ldap_modify($this->conn, $dn, $attribs);
	}

	/**
	 * Renames a LDAP entity.
	 * 
	 * @throws \gossi\ldap\LdapException If the rename fails.
	 * @param String $dn The distinguished name of a LDAP entity.
	 * @param String $newrdn The new RDN.
	 * @param String $newparent The new parent/superior entry.
	 * @param boolean $deleteoldrdn If true the old RDN value(s) is removed, else the old RDN value(s) is retained as non-distinguished values of the entry.
	 * @return boolean Returns true on success or false on failure.
	 */
	public function rename($dn, $newrdn, $newparent, $deleteoldrdn) {
		$success = ldap_rename($this->conn, $dn, $newrdn, $newparent, $deleteoldrdn);
		if (ldap_errno($this->conn)) {
			throw new LdapException(ldap_error($this->conn), ldap_errno($this->conn));
		}
		return $success;
	}

	/**
	 * Performs a ldap-search on the provided baseDN with your filter in <code>Subtree</code> scope
	 *
	 * @throws \gossi\ldap\LdapException If the search fails.
	 * @param String $baseDN The base DN for the directory.
	 * @param String $filter The search filter can be simple or advanced, using boolean operators in the format described in the LDAP documentation.
	 * @param array $attributes 
	 * 		An array of the required attributes, e.g. array("mail", "sn", "cn"). Note that the "dn" is always returned irrespective of which attributes types are requested.
	 * 		Using this parameter is much more efficient than the default action (which is to return all attributes and their associated values). The use of this parameter should therefore be considered good practice.
	 * @param int $attrsonly Should be set to 1 if only attribute types are wanted. If set to 0 both attributes types and attribute values are fetched which is the default behaviour.
	 * @param int $sizelimit 
	 * 		Enables you to limit the count of entries fetched. Setting this to 0 means no limit.
	 * 		This parameter can NOT override server-side preset sizelimit. You can set it lower though.
	 * 		Some directory server hosts will be configured to return no more than a preset number of entries. If this occurs, the server will indicate that it has only returned a partial results set. This also occurs if you use this parameter to limit the count of fetched entries.
	 * @param int $timelimit 
	 * 		Sets the number of seconds how long is spend on the search. Setting this to 0 means no limit.
	 * 		This parameter can NOT override server-side preset timelimit. You can set it lower though.
	 * @param int $deref Specifies how aliases should be handled during the search. It can be one of the following: LDAP_DEREF_NEVER - (default) aliases are never dereferenced.
	 * @return \gossi\ldap\LdapResult The search result.
	 */
	public function search($baseDN, $filter = '(objectClass=*)', $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
		$result = @ldap_search($this->conn, $baseDN, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
		if (ldap_errno($this->conn)) {
			throw new LdapException(ldap_error($this->conn), ldap_errno($this->conn));
		}

		return new LdapResult($this->conn, $result);
	}

	/**
	 * Performs a ldap-search on the provided baseDN with your filter in <code>Base</code> scope
	 *
	 * @throws \gossi\ldap\LdapException If the search fails.
	 * @param String $baseDN The base DN for the directory.
	 * @param String $filter The search filter can be simple or advanced, using boolean operators in the format described in the LDAP documentation.
	 * @param array $attributes 
	 * 		An array of the required attributes, e.g. array("mail", "sn", "cn"). Note that the "dn" is always returned irrespective of which attributes types are requested.
	 * 		Using this parameter is much more efficient than the default action (which is to return all attributes and their associated values). The use of this parameter should therefore be considered good practice.
	 * @param int $attrsonly Should be set to 1 if only attribute types are wanted. If set to 0 both attributes types and attribute values are fetched which is the default behaviour.
	 * @param int $sizelimit 
	 * 		Enables you to limit the count of entries fetched. Setting this to 0 means no limit.
	 * 		This parameter can NOT override server-side preset sizelimit. You can set it lower though.
	 * 		Some directory server hosts will be configured to return no more than a preset number of entries. If this occurs, the server will indicate that it has only returned a partial results set. This also occurs if you use this parameter to limit the count of fetched entries.
	 * @param int $timelimit 
	 * 		Sets the number of seconds how long is spend on the search. Setting this to 0 means no limit.
	 * 		This parameter can NOT override server-side preset timelimit. You can set it lower though.
	 * @param int $deref Specifies how aliases should be handled during the search. It can be one of the following: LDAP_DEREF_NEVER - (default) aliases are never dereferenced.
	 * @return \gossi\ldap\LdapResult The search result.
	 */
	public function searchBase($baseDN, $filter = '(objectClass=*)', $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
		$result = @ldap_read($this->conn, $baseDN, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
		if (ldap_errno($this->conn)) {
			throw new LdapException(ldap_error($this->conn), ldap_errno($this->conn));
		}

		return new LdapResult($this->conn, $result);
	}

	/**
	 * Performs a ldap-search on the provided baseDN with your filter in <code>One</code> scope
	 *
	 * @throws \gossi\ldap\LdapException If the search fails.
	 * @param String $baseDN The base DN for the directory.
	 * @param String $filter The search filter can be simple or advanced, using boolean operators in the format described in the LDAP documentation.
	 * @param array $attributes 
	 * 		An array of the required attributes, e.g. array("mail", "sn", "cn"). Note that the "dn" is always returned irrespective of which attributes types are requested.
	 * 		Using this parameter is much more efficient than the default action (which is to return all attributes and their associated values). The use of this parameter should therefore be considered good practice.
	 * @param int $attrsonly Should be set to 1 if only attribute types are wanted. If set to 0 both attributes types and attribute values are fetched which is the default behaviour.
	 * @param int $sizelimit 
	 * 		Enables you to limit the count of entries fetched. Setting this to 0 means no limit.
	 * 		This parameter can NOT override server-side preset sizelimit. You can set it lower though.
	 * 		Some directory server hosts will be configured to return no more than a preset number of entries. If this occurs, the server will indicate that it has only returned a partial results set. This also occurs if you use this parameter to limit the count of fetched entries.
	 * @param int $timelimit 
	 * 		Sets the number of seconds how long is spend on the search. Setting this to 0 means no limit.
	 * 		This parameter can NOT override server-side preset timelimit. You can set it lower though.
	 * @param int $deref Specifies how aliases should be handled during the search. It can be one of the following: LDAP_DEREF_NEVER - (default) aliases are never dereferenced.
	 * @return \gossi\ldap\LdapResult The search result.
	 */
	public function searchOne($baseDN, $filter = '(objectClass=*)', $attributes = array(), $attrsonly = 0, $sizelimit = 0, $timelimit = 0, $deref = LDAP_DEREF_NEVER) {
		$result = @ldap_list($this->conn, $baseDN, $filter, $attributes, $attrsonly, $sizelimit, $timelimit, $deref);
		if (ldap_errno($this->conn)) {
			throw new LdapException(ldap_error($this->conn), ldap_errno($this->conn));
		}

		return new LdapResult($this->conn, $result);
	}

}