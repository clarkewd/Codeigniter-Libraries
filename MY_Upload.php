<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/**
 * This will provides support for file upload arrays
 * when provided in the format of name="userfile[]"
 */

class MY_Upload extends CI_Upload {

	var $current_multi_loop;
	var $multi_file_array;
	var $multi_confirm;
	var $data_array;
	
	/**
	 * Extended do upload - Includes multi-part array
	 *
	 * @access	public
	 * @return	bool
	 */
	function do_upload($field = 'userfile')
	{
		// Is $_FILES[$field] set? If not, no reason to continue.
		if ( ! isset($_FILES[$field]))
		{
			$this->set_error('upload_no_file_selected');
			return FALSE;
		}
	
		// Is the upload path valid?
		if ( ! $this->validate_upload_path())
		{
			// errors will already be set by validate_upload_path() so just return FALSE
			return FALSE;
		}
	
		// Added for multiple uploads
		// This is a multi part array
		if (is_array($_FILES[$field]['tmp_name']))
		{
			foreach ($_FILES[$field] as $k => $v)
		    {
				$i = 0;
		        foreach ($v as $item)
		        {
					$this->current_multi_loop = $k;
					$this->multi_file_array[$i][$k] = $item;
					$i++;
				}
			}
			
		    for ($i=0;$i<count($this->multi_file_array);$i++)
		    {
		        $_FILES[$field] = $this->multi_file_array[$i];
		
				$r[] = $this->do_upload($field);

				$this->data_array[$i] = $this->data(FALSE);
			}
			
			return (in_array(TRUE, $r) ? TRUE : FALSE);
		}

		// Was the file able to be uploaded? If not, determine the reason why.
		if ( ! is_uploaded_file($_FILES[$field]['tmp_name']))
		{
			$error = ( ! isset($_FILES[$field]['error'])) ? 4 : $_FILES[$field]['error'];

			switch($error)
			{
				case 1:	// UPLOAD_ERR_INI_SIZE
					$this->set_error('upload_file_exceeds_limit');
					break;
				case 2: // UPLOAD_ERR_FORM_SIZE
					$this->set_error('upload_file_exceeds_form_limit');
					break;
				case 3: // UPLOAD_ERR_PARTIAL
				   $this->set_error('upload_file_partial');
					break;
				case 4: // UPLOAD_ERR_NO_FILE
				   $this->set_error('upload_no_file_selected');
					break;
				case 6: // UPLOAD_ERR_NO_TMP_DIR
					$this->set_error('upload_no_temp_directory');
					break;
				case 7: // UPLOAD_ERR_CANT_WRITE
					$this->set_error('upload_unable_to_write_file');
					break;
				case 8: // UPLOAD_ERR_EXTENSION
					$this->set_error('upload_stopped_by_extension');
					break;
				default :  
					$this->set_error('upload_no_file_selected');
					break;
			}

			return FALSE;
		}

		// Set the uploaded data as class variables
		$this->file_temp = $_FILES[$field]['tmp_name'];		
		$this->file_size = $_FILES[$field]['size'];	
		$this->file_type = preg_replace("/^(.+?);.*$/", "\\1", $_FILES[$field]['type']);
		$this->file_type = strtolower(trim(stripslashes($this->file_type), '"'));
		$this->file_name = $this->_prep_filename($_FILES[$field]['name']);
		$this->file_ext	 = $this->get_extension($this->file_name);
		$this->client_name = $this->file_name;

		// Is the file type allowed to be uploaded?
		if ( ! $this->is_allowed_filetype())
		{
			$this->set_error('upload_invalid_filetype');
			return FALSE;
		}
			
		// if we're overriding, let's now make sure the new name and type is allowed
		if ($this->_file_name_override != '')
		{
			$this->file_name = $this->_prep_filename($this->_file_name_override);
			$this->file_ext  = $this->get_extension($this->file_name);

			if ( ! $this->is_allowed_filetype(TRUE))
			{
				$this->set_error('upload_invalid_filetype');
				return FALSE;				
			}
		}
	
		// Convert the file size to kilobytes
		if ($this->file_size > 0)
		{
			$this->file_size = round($this->file_size/1024, 2);
		}

		// Is the file size within the allowed maximum?
		if ( ! $this->is_allowed_filesize())
		{
			$this->set_error('upload_invalid_filesize');
			return FALSE;
		}

		// Are the image dimensions within the allowed size?
		// Note: This can fail if the server has an open_basdir restriction.
		if ( ! $this->is_allowed_dimensions())
		{
			$this->set_error('upload_invalid_dimensions');
			return FALSE;
		}

		// Sanitize the file name for security
		$this->file_name = $this->clean_file_name($this->file_name);
	
		// Truncate the file name if it's too long
		if ($this->max_filename > 0)
		{
			$this->file_name = $this->limit_filename_length($this->file_name, $this->max_filename);
		}

		// Remove white spaces in the name
		if ($this->remove_spaces == TRUE)
		{
			$this->file_name = preg_replace("/\s+/", "_", $this->file_name);
		}

		/*
		 * Validate the file name
		 * This function appends an number onto the end of
		 * the file if one with the same name already exists.
		 * If it returns false there was a problem.
		 */
		$this->orig_name = $this->file_name;

		if ($this->overwrite == FALSE)
		{
			$this->file_name = $this->set_filename($this->upload_path, $this->file_name);
		
			if ($this->file_name === FALSE)
			{
				return FALSE;
			}
		}

		/*
		 * Move the file to the final destination
		 * To deal with different server configurations
		 * we'll attempt to use copy() first.  If that fails
		 * we'll use move_uploaded_file().  One of the two should
		 * reliably work in most environments
		 */
		if ( ! @copy($this->file_temp, $this->upload_path.$this->file_name))
		{
			if ( ! @move_uploaded_file($this->file_temp, $this->upload_path.$this->file_name))
			{
				 $this->set_error('upload_destination_error');
				 return FALSE;
			}
		}
	
		/*
		 * Run the file through the XSS hacking filter
		 * This helps prevent malicious code from being
		 * embedded within a file.  Scripts can easily
		 * be disguised as images or other file types.
		 */
		if ($this->xss_clean == TRUE)
		{
			$this->do_xss_clean();
		}

		/*
		 * Set the finalized image dimensions
		 * This sets the image width/height (assuming the
		 * file was an image).  We use this information
		 * in the "data" function.
		 */
		$this->set_image_properties($this->upload_path.$this->file_name);

		return TRUE;
	}

	/**
	 * Finalized Data Array
	 *	
	 * Returns an associative array containing all of the information
	 * related to the upload, allowing the developer easy access in one array.
	 *
	 * @access	public
	 * @param 	bool	Whether we are in the array loop
	 * @return	array
	 */	
	function data($in = FALSE)
	{
		if ($in === TRUE OR empty($this->multi_file_array))
		{
			return array (
							'file_name'			=> $this->file_name,
							'file_type'			=> $this->file_type,
							'file_path'			=> $this->upload_path,
							'full_path'			=> $this->upload_path.$this->file_name,
							'raw_name'			=> str_replace($this->file_ext, '', $this->file_name),
							'orig_name'			=> $this->orig_name,
							'client_name'		=> $this->client_name,
							'file_ext'			=> $this->file_ext,
							'file_size'			=> $this->file_size,
							'is_image'			=> $this->is_image(),
							'image_width'		=> $this->image_width,
							'image_height'		=> $this->image_height,
							'image_type'		=> $this->image_type,
							'image_size_str'	=> $this->image_size_str,
						);
		}
		else
		{
			return $this->multi_file_array;
		}
	}

	// --------------------------------------------------------------------
	
	/**
	 * Set an error message
	 *
	 * @access	public
	 * @param	string
	 * @param	int		--Optional file id, if it is multiple	
	 * @return	void
	 */	
	function set_error($msg)
	{
		$CI =& get_instance();	
		$CI->lang->load('upload');
		
		if (is_array($msg))
		{	
			foreach ($msg as $val)
			{
				$msg = ($CI->lang->line($val) == FALSE) ? $val : $CI->lang->line($val);
				
				// Array of files ID
				if (empty($this->current_multi_loop))
				{	
					$this->error_msg[] = $msg;
					log_message('error', $msg);
				}
				else
				{
					$this->error_msg[$this->current_multi_loop][] = $msg;
					log_message('error', $msg);
				}
			}		
		}
		else
		{
			if (empty($this->current_multi_loop))
			{
				$msg = ($CI->lang->line($msg) == FALSE) ? $msg : $CI->lang->line($msg);
				$this->error_msg[] = $msg;
				log_message('error', $msg);
			}
			else
			{
				$msg = ($CI->lang->line($msg) == FALSE) ? $msg : $CI->lang->line($msg);
				$this->error_msg[$this->current_multi_loop][] = $msg;
				log_message('error', $msg);
			}
		}
	}
	
	// --------------------------------------------------------------------
	
	/**
	 * Display the error message
	 *
	 * @access	public
	 * @param	string
	 * @param	string
	 * @return	string
	 */	
	function display_errors($open = '<p>', $close = '</p>')
	{
		$str = '';
		foreach ($this->error_msg as $val)
		{
			if (is_array($val))
			{
				foreach($val as $multi)
				{
					$str .= $open.$multi.$close;						
				}
			}
			else
			{
				$str .= $open.$val.$close;	
			}
		}
	
		return $str;
	}
	
}