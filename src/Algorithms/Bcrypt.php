<?php

/*
Its me, gagiyin. I made some fixes on the code, because I had a few errors located in Bcrypt class. 

What i fixed:

--

Error1:
	$cost = self::$_defaultCost; <- i had errors with this
Fix1: 	
	if (empty($cost)) {
	    $cost = $this->_defaultCost;
	}

--

Error2:
	return substr($salt, 0, self::$_saltLength);
Fix2:
	return substr($salt, 0, $this->_saltLength);
--

Error3:
	return sprintf('$%s$%02d$%s$', self::$_saltPrefix, $cost, $salt);
Fix3:
	return sprintf('$%s$%02d$%s$', $this->_saltPrefix, $cost, $salt);

--

Reason: $_defaultCost is not static, but an objective variable, so it needs $this->_defaultCost instead of self::(..)
Hope it works, respect to the authors

*/

/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

/**
 * Bcrypt hashing class
 * 
 * @author Thiago Belem <contato@thiagobelem.net>
 * @link   https://gist.github.com/3438461
 */
class Bcrypt extends Algorithm {

    /**
     * Default salt prefix
     * 
     * @see http://www.php.net/security/crypt_blowfish.php
     * 
     * @var string
     */
    protected $_saltPrefix = '2a';
    
    /**
     * Default hashing cost (4-31)
     * 
     * @var integer
     */
    protected $_defaultCost = 14;

    /**
     * Salt limit length
     * 
     * @var integer
     */
    protected $_saltLength = 22;

    /**
     * Hash a string
     * 
     * @param  string  $string The string
     * @param  integer $cost   The hashing cost
     * 
     * @return string
     */
    public function hash(string $string, $cost = null) {
        if (empty($cost)) {
            $cost = $this->_defaultCost;
        }

        // Salt
        $salt = $this->generate_random_salt();

        // Hash string
        $hashString = $this->__generate_hash_string((int)$cost, $salt);

        return crypt($string, $hashString);
    }

    /**
     * Check a hashed string
     * 
     * @param  string $string The string
     * @param  string $hash   The hash
     * 
     * @return boolean
     */
    public function verify(string $password, string $hash) {
        return (crypt($password, $hash) === $hash);
    }

    /**
     * Generate a random base64 encoded salt
     * 
     * @return string
     */
    private function generate_random_salt() {
        // Salt seed
        $seed = uniqid(mt_rand(), true);

        // Generate salt
        $salt = base64_encode($seed);
        $salt = str_replace('+', '.', $salt);

        return substr($salt, 0, $this->_saltLength);
    }

    /**
     * Build a hash string for crypt()
     * 
     * @param  integer $cost The hashing cost
     * @param  string $salt  The salt
     * 
     * @return string
     */
    private function __generate_hash_string($cost, $salt) {
        return sprintf('$%s$%02d$%s$', $this->_saltPrefix, $cost, $salt);
    }

}
