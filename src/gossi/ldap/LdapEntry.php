<?php
namespace gossi\ldap;

/**
 * This class represents an LDAP Entry.
 * 
 * @author Thomas Gossmann
 */
class LdapEntry {

	private $conn;
	private $entry;
	private $dn;

	/**
	 * Constructs a new LdapEntry.
	 * 
	 * @param RessourceIdentifier $conn A LDAP link identifier, returned by ldap_connect.
	 * @param RessourceIdentifier $entry A LDAP link identifier, returned by ldap_first_entry or ldap_next_entry. 
	 */
	function __construct($conn, $entry) {
		$this->conn = $conn;
		$this->entry = $entry;
		$this->dn = ldap_get_dn($this->conn, $this->entry);
	}

	/**
	 * Adds attributes to that entry.
	 * 
	 * @param array $attribs The new attributes.
	 * @return boolean Returns true on success and false on failure.
	 */
	public function add($attribs) {
		return ldap_mod_add($this->conn, $this->dn, $attribs);
	}

	/**
	 * Deletes attributes from that entry.
	 *
	 * @param array $attribs The attributes to delete.
	 * @return boolean Returns true on success and false on failure.
	 */
	public function delete($attribs) {
		return ldap_mod_del($this->conn, $this->dn, $attribs);
	}

	/**
	 * Returns the first value for the given attribute
	 * 
	 * @param String $attribute The given attribute.
	 * @return String The first value for the given attribute or <code>null</code> if the attribute does not exist. 
	 */
	public function getFirst($attribute) {
		if ($attributes = $this->getAll($attribute)) {
			return $attributes[0];
		} else {
			return null;
		}
	}

	/**
	 * Returns all the values for the given attribute
	 *
	 * @param String $attribute The given attribute.
	 * @return array The values for the given attribute or <code>null</code> if the attribute does not exist.
	 */
	public function getAll($attribute) {
		$values = ldap_get_values($this->conn, $this->entry, $attribute);

		$allValues = array();

		if ($values && $values['count']) {
			for ($i = 0; $i < $values['count']; $i++) {
				$allValues[] = $values[$i];
			}

			return $allValues;
		} else {
			return null;
		}
	}

	/**
	 * Returns the first value for the given attribute
	 *
	 * @param String $attribute The given attribute.
	 * @return String The first value for the given attribute or <code>null</code> if the attribute does not exist.
	 */
	public function get($attribute) {
		return $this->getFirst($attribute);
	}

	/**
	 * Returns the distinguished name for that LDAP entity.
	 * 
	 * @return String The distinguished name.
	 */
	public function getDN() {
		return $this->dn; 
	}

	/**
	 * Modifies attributes on that entry.
	 *
	 * @param array $attribs The attributes to modify.
	 * @return boolean Returns true on success and false on failure.
	 */
	public function modify($attribs) {
		return ldap_mod_replace($this->conn, $this->dn, $attribs);
	}
}
?>