define([
  'backbone'
], function(
  Backbone
) {
  return Backbone.Model.extend({
    defaults : {
      'number'    : '',
      'base'      : 'dec',
      'converted' : null,
      'error'     : null
    },

    initialize : function() {
      this.listenTo(this, 'change:number change:base', this.convert);
      this.listenTo(this, 'sync', this.update);
      this.listenTo(this, 'error', this.error);
    },

    url : function() {
      return '/convert/' + this.get('base');
    },

    convert : function() {
      if (0 < this.get('number').length) {
        this.save();
        return;
      }

      /* No number currently set */
      this.update(this, null, {});
    },

    update : function(model, response, options) {
      this.set('converted', response);
      this.set('error', null);
    },

    error : function(model, xhr, options) {
      this.set('error', JSON.parse(xhr.responseText));

      /* That conversion didn't work, must set converted to match
         the number, where 'null' currently is the best guess */
      this.set('converted', null);
    }
  });
});
